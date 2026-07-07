#include "pch.h"
#include "ElfHelper.h"
PRAGMA_WARNING(push, 0)
#include <platform/elf.h>
#if defined(DART_TARGET_OS_MACOS)
// old dart version has no mach_o.h
//#include <platform/mach_o.h>
#endif
PRAGMA_WARNING(pop)
#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>
#if defined(_WIN32) || defined(WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
//#include <dlfcn.h>
#include <sys/mman.h>
#endif // #if defined(_WIN32) || defined(WIN32)

struct ElfIdent {
	uint8_t ei_magic[4];
	uint8_t ei_class;
	uint8_t ei_data;
	uint8_t ei_version;
	uint8_t ei_osabi;
	uint8_t ei_abiversion;
	uint8_t pad1[7];
};

using namespace dart::elf;

static constexpr uint32_t MH_MAGIC_64 = 0xfeedfacf;
static constexpr uint32_t FAT_MAGIC = 0xcafebabe;
static constexpr uint32_t FAT_MAGIC_64 = 0xcafebabf;
static constexpr uint32_t LC_SEGMENT_64 = 0x19;
static constexpr uint32_t LC_SYMTAB = 0x2;
static constexpr uint32_t CPU_TYPE_ARM64 = 0x0100000c;
static constexpr uint32_t CPU_TYPE_X86_64 = 0x01000007;
static uint32_t g_preferred_cpu_type = CPU_TYPE_ARM64;

static uint32_t read_be32(const uint8_t* p)
{
	return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

static uint64_t read_be64(const uint8_t* p)
{
	return (uint64_t(read_be32(p)) << 32) | uint64_t(read_be32(p + 4));
}

struct MachOSlice {
	const uint8_t* ptr;
	size_t size;
};

struct MachOSection {
	uint64_t addr;
	uint64_t size;
	uint32_t offset;
};

static MachOSlice select_macho_slice(const uint8_t* file, size_t size)
{
	if (size < 4)
		throw std::invalid_argument("Mach-O: File too small");

	const auto magic_be = read_be32(file);
	if (magic_be != FAT_MAGIC && magic_be != FAT_MAGIC_64) {
		if (*(const uint32_t*)file != MH_MAGIC_64)
			throw std::invalid_argument("Mach-O: Invalid magic header");
		return { file, size };
	}

	const auto nfat = read_be32(file + 4);
	size_t off = 8;
	MachOSlice first{ nullptr, 0 };
	MachOSlice arm64{ nullptr, 0 };
	for (uint32_t i = 0; i < nfat; i++) {
		uint32_t cputype;
		uint64_t slice_off;
		uint64_t slice_size;
		if (magic_be == FAT_MAGIC_64) {
			if (off + 32 > size)
				throw std::invalid_argument("Mach-O: Truncated fat header");
			cputype = read_be32(file + off);
			slice_off = read_be64(file + off + 8);
			slice_size = read_be64(file + off + 16);
			off += 32;
		}
		else {
			if (off + 20 > size)
				throw std::invalid_argument("Mach-O: Truncated fat header");
			cputype = read_be32(file + off);
			slice_off = read_be32(file + off + 8);
			slice_size = read_be32(file + off + 12);
			off += 20;
		}
		if (slice_off > size || slice_size > size - slice_off)
			throw std::invalid_argument("Mach-O: Slice outside file");
		MachOSlice slice{ file + slice_off, (size_t)slice_size };
		if (first.ptr == nullptr)
			first = slice;
		if (cputype == CPU_TYPE_ARM64)
			arm64 = slice;
		if (cputype == g_preferred_cpu_type)
			return slice;
	}

	if (arm64.ptr != nullptr)
		return arm64;
	if (first.ptr != nullptr)
		return first;
	throw std::invalid_argument("Mach-O: Empty fat binary");
}

void ElfHelper::SetPreferredArch(const char* arch)
{
	if (arch == nullptr || arch[0] == '\0' || strcmp(arch, "arm64") == 0) {
		g_preferred_cpu_type = CPU_TYPE_ARM64;
	}
	else if (strcmp(arch, "x64") == 0 || strcmp(arch, "x86_64") == 0) {
		g_preferred_cpu_type = CPU_TYPE_X86_64;
	}
	else {
		throw std::invalid_argument("Unsupported architecture. Expected arm64 or x64");
	}
}

static const uint8_t* macho_va_to_ptr(uint64_t addr, const uint8_t* macho, const std::vector<MachOSection>& sections)
{
	for (const auto& section : sections) {
		if (section.addr <= addr && addr < section.addr + section.size) {
			const uint64_t rel = addr - section.addr;
			if (rel > std::numeric_limits<uint32_t>::max())
				break;
			return macho + section.offset + rel;
		}
	}
	return nullptr;
}

static LibAppInfo find_macho_snapshots(const uint8_t* file, size_t size)
{
	auto slice = select_macho_slice(file, size);
	const uint8_t* macho = slice.ptr;
	if (slice.size < 32 || *(const uint32_t*)macho != MH_MAGIC_64)
		throw std::invalid_argument("Mach-O: Support only little-endian 64-bit slices");

	const auto ncmds = *(const uint32_t*)(macho + 16);
	const auto sizeofcmds = *(const uint32_t*)(macho + 20);
	if (32ull + sizeofcmds > slice.size)
		throw std::invalid_argument("Mach-O: Load commands outside slice");

	std::vector<MachOSection> sections;
	const uint8_t* symtab = nullptr;
	uint32_t nsyms = 0;
	const char* strtab = nullptr;
	uint32_t strsize = 0;

	size_t lc_off = 32;
	for (uint32_t i = 0; i < ncmds; i++) {
		if (lc_off + 8 > slice.size)
			throw std::invalid_argument("Mach-O: Truncated load command");
		const auto cmd = *(const uint32_t*)(macho + lc_off);
		const auto cmdsize = *(const uint32_t*)(macho + lc_off + 4);
		if (cmdsize < 8 || lc_off + cmdsize > slice.size)
			throw std::invalid_argument("Mach-O: Invalid load command size");

		if (cmd == LC_SEGMENT_64) {
			if (cmdsize < 72)
				throw std::invalid_argument("Mach-O: Invalid LC_SEGMENT_64 size");
			const auto nsects = *(const uint32_t*)(macho + lc_off + 64);
			size_t sec_off = lc_off + 72;
			for (uint32_t j = 0; j < nsects; j++) {
				if (sec_off + 80 > lc_off + cmdsize)
					throw std::invalid_argument("Mach-O: Invalid section_64 table");
				MachOSection section{
					.addr = *(const uint64_t*)(macho + sec_off + 32),
					.size = *(const uint64_t*)(macho + sec_off + 40),
					.offset = *(const uint32_t*)(macho + sec_off + 48),
				};
				if (section.offset != 0 && section.offset <= slice.size && section.size <= slice.size - section.offset)
					sections.push_back(section);
				sec_off += 80;
			}
		}
		else if (cmd == LC_SYMTAB) {
			if (cmdsize < 24)
				throw std::invalid_argument("Mach-O: Invalid LC_SYMTAB size");
			const auto symoff = *(const uint32_t*)(macho + lc_off + 8);
			nsyms = *(const uint32_t*)(macho + lc_off + 12);
			const auto stroff = *(const uint32_t*)(macho + lc_off + 16);
			strsize = *(const uint32_t*)(macho + lc_off + 20);
			if (symoff > slice.size || uint64_t(nsyms) * 16 > slice.size - symoff || stroff > slice.size || strsize > slice.size - stroff)
				throw std::invalid_argument("Mach-O: Symbol table outside slice");
			symtab = macho + symoff;
			strtab = (const char*)macho + stroff;
		}
		lc_off += cmdsize;
	}

	if (symtab == nullptr || strtab == nullptr)
		throw std::invalid_argument("Mach-O: Cannot find symbol table");

	const uint8_t* vm_snapshot_data = nullptr;
	const uint8_t* vm_snapshot_instructions = nullptr;
	const uint8_t* isolate_snapshot_data = nullptr;
	const uint8_t* isolate_snapshot_instructions = nullptr;
	for (uint32_t i = 0; i < nsyms; i++) {
		const uint8_t* nlist = symtab + i * 16;
		const auto n_strx = *(const uint32_t*)nlist;
		if (n_strx == 0 || n_strx >= strsize)
			continue;
		const char* name = strtab + n_strx;
		const uint64_t value = *(const uint64_t*)(nlist + 8);
		const uint8_t* ptr = macho_va_to_ptr(value, macho, sections);
		if (ptr == nullptr)
			continue;

		if (strcmp(name, kVmSnapshotDataAsmSymbol) == 0) {
			vm_snapshot_data = ptr;
		}
		else if (strcmp(name, kVmSnapshotInstructionsAsmSymbol) == 0) {
			vm_snapshot_instructions = ptr;
		}
		else if (strcmp(name, kIsolateSnapshotDataAsmSymbol) == 0) {
			isolate_snapshot_data = ptr;
		}
		else if (strcmp(name, kIsolateSnapshotInstructionsAsmSymbol) == 0) {
			isolate_snapshot_instructions = ptr;
		}
	}

	if (vm_snapshot_data == nullptr)
		throw std::invalid_argument("Mach-O: Cannot find Dart VM Snapshot Data");
	if (vm_snapshot_instructions == nullptr)
		throw std::invalid_argument("Mach-O: Cannot find Dart VM Snapshot Instructions");
	if (isolate_snapshot_data == nullptr)
		throw std::invalid_argument("Mach-O: Cannot find Dart Isolate Snapshot Data");
	if (isolate_snapshot_instructions == nullptr)
		throw std::invalid_argument("Mach-O: Cannot find Dart Isolate Snapshot Instructions");

	return LibAppInfo{
		.lib = macho,
		.vm_snapshot_data = vm_snapshot_data,
		.vm_snapshot_instructions = vm_snapshot_instructions,
		.isolate_snapshot_data = isolate_snapshot_data,
		.isolate_snapshot_instructions = isolate_snapshot_instructions,
	};
}

#ifdef _WIN32
struct MappedFile {
	void* mem;
	size_t size;
};

static MappedFile load_map_file(const char* path)
{
	HANDLE hFile = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("\nCannot find %s\n", path);
		return { NULL, 0 };
	}
	LARGE_INTEGER fileSize;
	GetFileSizeEx(hFile, &fileSize);

	// because Dart API requires only snapshot buffer addresses (no relative access across snapshot),
	//   so we can just mapping a whole file and find address of snapshots
	HANDLE hMapFile = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMapFile == INVALID_HANDLE_VALUE)
		return { NULL, 0 };

	// need RW because dart initialization need writing data in BSS
	void* mem = MapViewOfFile(hMapFile, FILE_MAP_COPY, 0, 0, 0);
	CloseHandle(hMapFile);

	CloseHandle(hFile);
	return { mem, (size_t)fileSize.QuadPart };
}
#else
struct MappedFile {
	void* mem;
	size_t size;
};

static MappedFile load_map_file(const char* path)
{
	// need RW because dart initialization need writing data in BSS
	int fd = open(path, O_RDONLY);
	if (fd == -1) {
		printf("\nCannot find %s\n", path);
		return { NULL, 0 };
	}
	struct stat st;

	fstat(fd, &st);
	void* mem = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

	close(fd);
	return { mem, (size_t)st.st_size };
}
#endif

LibAppInfo ElfHelper::findSnapshots(const uint8_t* elf)
{
	const auto* hdr = (const ElfHeader*)elf;
	if (hdr->section_table_entry_size != sizeof(SectionHeader))
		throw std::invalid_argument("ELF: Invalid section entry size");

	const auto* section = (SectionHeader*)(elf + hdr->section_table_offset);
	const auto sh_num = hdr->num_section_headers;

	// find .dynstr and .dynsym sections, so we can map the section names
	const char* dynstr = nullptr;
	const Symbol* dynsym = nullptr;
	const Symbol* dynsym_end = nullptr;
	for (uint16_t i = 0; i < sh_num; i++, section++) {
		if (section->type == SectionHeaderType::SHT_STRTAB && dynstr == nullptr) {
			// we want only .dynstr for .dynsym
			const char* strtab = (const char*)elf + section->file_offset;
			const char* last = strtab + section->file_size;
			const char* s_first = kVmSnapshotDataAsmSymbol;
			const char* s_last = s_first + strlen(kVmSnapshotDataAsmSymbol) + 1;
			//if (memmem(strtab, section->s_size, kVmSnapshotDataAsmSymbol, strlen(kVmSnapshotDataAsmSymbol))) {
			if (std::search(strtab, last, s_first, s_last) != last) {
				// found it
				dynstr = strtab;
			}
		}
		if (section->type == SectionHeaderType::SHT_DYNSYM) {
			if (section->entry_size != sizeof(Symbol))
				throw std::invalid_argument("ELF: Invalid DYNSYM entry size");
			dynsym = (Symbol*)(elf + section->file_offset);
			dynsym_end = (Symbol*)(elf + section->file_offset + section->file_size);
		}
		if (dynsym != nullptr && dynstr != nullptr)
			break;
	}

	// find the required symbol addresses
	const uint8_t* vm_snapshot_data = nullptr;
	const uint8_t* vm_snapshot_instructions = nullptr;
	const uint8_t* isolate_snapshot_data = nullptr;
	const uint8_t* isolate_snapshot_instructions = nullptr;
	for (; dynsym < dynsym_end; dynsym++) {
		if (dynsym->info == 0)
			continue;

		const char* name = dynstr + dynsym->name;
		// Note: sym_size is no needed for dart VM (its blob contains size)
		if (strcmp(name, kVmSnapshotDataAsmSymbol) == 0) {
			vm_snapshot_data = elf + dynsym->value;
		}
		else if (strcmp(name, kVmSnapshotInstructionsAsmSymbol) == 0) {
			vm_snapshot_instructions = elf + dynsym->value;
		}
		else if (strcmp(name, kIsolateSnapshotDataAsmSymbol) == 0) {
			isolate_snapshot_data = elf + dynsym->value;
		}
		else if (strcmp(name, kIsolateSnapshotInstructionsAsmSymbol) == 0) {
			isolate_snapshot_instructions = elf + dynsym->value;
		}
	}

	if (vm_snapshot_data == nullptr)
		throw std::invalid_argument("ELF: Cannot find Dart VM Snapshot Data");
	if (vm_snapshot_instructions == nullptr)
		throw std::invalid_argument("ELF: Cannot find Dart VM Snapshot Instructions");
	if (isolate_snapshot_data == nullptr)
		throw std::invalid_argument("ELF: Cannot find Dart Isolate Snapshot Data");
	if (isolate_snapshot_instructions == nullptr)
		throw std::invalid_argument("ELF: Cannot find Dart Isolate Snapshot Instructions");

	return LibAppInfo{
		.lib = elf,
		.vm_snapshot_data = vm_snapshot_data,
		.vm_snapshot_instructions = vm_snapshot_instructions,
		.isolate_snapshot_data = isolate_snapshot_data,
		.isolate_snapshot_instructions = isolate_snapshot_instructions,
	};
}

LibAppInfo ElfHelper::MapLibAppSo(const char* path)
{
	MappedFile mapped = load_map_file(path);
	void* lib = mapped.mem;
	if (lib == nullptr)
		throw std::invalid_argument("Cannot map libapp/App file");
	// quick and dirty parsing ELF to get symbol addresses
	uint8_t* elf = (uint8_t*)(lib);
	const auto magic = *(const uint32_t*)elf;
	if (magic == MH_MAGIC_64 || read_be32(elf) == FAT_MAGIC || read_be32(elf) == FAT_MAGIC_64)
		return find_macho_snapshots(elf, mapped.size);

	const auto* hdr = (ElfHeader*)elf;
	const auto* ident = (ElfIdent*)hdr->ident;
	if (memcmp(ident->ei_magic, "\x7f" "ELF", 4) != 0)
		throw std::invalid_argument("ELF: Invalid magic header"); // need ELF file
	if (ident->ei_data != 1)
		throw std::invalid_argument("ELF: Support only little endian"); // expect little-endian

	if (ident->ei_class != ELFCLASS64) { // 1 is 32 bits, 2 is 64 bits
		throw std::invalid_argument("ELF: Support only 64 bits"); // support only 64 bits
	}
	// expected e_machine
	//   3: x86, 0x28: ARM
	//   0x3e: x86-64, 0xB7: Aarch64
	// EM_386, EM_ARM, EM_X86_64, EM_AARCH64
	//hdr->e_machine;

	return findSnapshots(elf);
}
