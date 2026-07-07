import io
import os
import re
import requests
import sys
import zipfile
import zlib
from struct import unpack, unpack_from

from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_E_MACHINE 
from elftools.elf.sections import SymbolTableSection

CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000c
FAT_MAGIC = 0xcafebabe
FAT_MAGIC_64 = 0xcafebabf
MH_MAGIC_64 = 0xfeedfacf
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2

CPU_ARCH_NAMES = {
    CPU_TYPE_X86_64: 'x64',
    CPU_TYPE_ARM64: 'arm64',
}

SNAPSHOT_SYMBOLS = {
    '_kDartVmSnapshotData',
    '_kDartVmSnapshotInstructions',
    '_kDartIsolateSnapshotData',
    '_kDartIsolateSnapshotInstructions',
}

def _read_cstr(data: bytes, offset: int) -> str:
    if isinstance(data, memoryview):
        data = data.tobytes()
    end = data.index(b'\0', offset)
    return data[offset:end].decode()

def _macho_slice(data: bytes, preferred_arch: str = 'arm64'):
    magic = unpack_from('>I', data, 0)[0]
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        if unpack_from('<I', data, 0)[0] != MH_MAGIC_64:
            raise ValueError('Mach-O: invalid magic header')
        cputype = unpack_from('<i', data, 4)[0]
        return 0, len(data), CPU_ARCH_NAMES.get(cputype, str(cputype))

    nfat_arch = unpack_from('>I', data, 4)[0]
    archs = []
    off = 8
    for _ in range(nfat_arch):
        if magic == FAT_MAGIC_64:
            cputype, _, offset, size, _, _ = unpack_from('>IIQQII', data, off)
            off += 32
        else:
            cputype, _, offset, size, _ = unpack_from('>IIIII', data, off)
            off += 20
        archs.append((CPU_ARCH_NAMES.get(cputype, str(cputype)), offset, size))

    for arch, offset, size in archs:
        if arch == preferred_arch:
            return offset, size, arch
    for arch, offset, size in archs:
        if arch == 'arm64':
            return offset, size, arch
    return (*archs[0][1:], archs[0][0])

def _parse_macho(data: bytes, preferred_arch: str = 'arm64'):
    slice_off, slice_size, arch = _macho_slice(data, preferred_arch)
    blob = memoryview(data)[slice_off:slice_off + slice_size]
    if unpack_from('<I', blob, 0)[0] != MH_MAGIC_64:
        raise ValueError('Mach-O: support only little-endian 64-bit slices')

    _, cputype, _, _, ncmds, sizeofcmds, _, _ = unpack_from('<IiiIIIII', blob, 0)
    arch = CPU_ARCH_NAMES.get(cputype, arch)
    load_off = 32
    sections = []
    symtab = None
    build_platform = None
    for _ in range(ncmds):
        cmd, cmdsize = unpack_from('<II', blob, load_off)
        if cmd == LC_SEGMENT_64:
            seg = bytes(blob[load_off + 8:load_off + 24]).split(b'\0', 1)[0].decode()
            nsects = unpack_from('<I', blob, load_off + 64)[0]
            sec_off = load_off + 72
            for _ in range(nsects):
                sect = bytes(blob[sec_off:sec_off + 16]).split(b'\0', 1)[0].decode()
                sec_seg = bytes(blob[sec_off + 16:sec_off + 32]).split(b'\0', 1)[0].decode()
                addr, size = unpack_from('<QQ', blob, sec_off + 32)
                fileoff = unpack_from('<I', blob, sec_off + 48)[0]
                sections.append((sec_seg or seg, sect, addr, size, fileoff))
                sec_off += 80
        elif cmd == LC_SYMTAB:
            symtab = unpack_from('<IIII', blob, load_off + 8)
        elif cmd == 0x32:  # LC_BUILD_VERSION
            platform = unpack_from('<I', blob, load_off + 8)[0]
            # PLATFORM_MACOS = 1, PLATFORM_IOS = 2
            if platform == 1:
                build_platform = 'macos'
            elif platform == 2:
                build_platform = 'ios'
        load_off += cmdsize

    if load_off > 32 + sizeofcmds:
        raise ValueError('Mach-O: load commands exceed header size')

    def va_to_fileoff(addr: int):
        for _, _, sec_addr, sec_size, fileoff in sections:
            if sec_addr <= addr < sec_addr + sec_size:
                return fileoff + (addr - sec_addr)
        raise ValueError(f'Mach-O: cannot map VA 0x{addr:x} to a file offset')

    symbols = {}
    if symtab is not None:
        symoff, nsyms, stroff, strsize = symtab
        strtab = blob[stroff:stroff + strsize]
        for i in range(nsyms):
            n_strx, n_type, n_sect, n_desc, n_value = unpack_from('<IBBHQ', blob, symoff + i * 16)
            if n_strx == 0 or n_strx >= strsize:
                continue
            name = _read_cstr(strtab, n_strx)
            if name in SNAPSHOT_SYMBOLS:
                symbols[name] = va_to_fileoff(n_value)

    section_data = {
        (seg, sect): bytes(blob[fileoff:fileoff + size])
        for seg, sect, _, size, fileoff in sections
        if fileoff != 0 and size != 0
    }
    return blob, symbols, section_data, arch, build_platform or 'macos'

def extract_snapshot_hash_flags(libapp_file, arch: str = None):
    with open(libapp_file, 'rb') as f:
        magic = f.read(4)
        f.seek(0)
        if magic in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf', b'\xcf\xfa\xed\xfe'):
            data = f.read()
            blob, symbols, _, _, _ = _parse_macho(data, arch or 'arm64')
            symoff = symbols.get('_kDartVmSnapshotData')
            if symoff is None:
                raise ValueError('Mach-O: Cannot find Dart VM Snapshot Data')
            assert len(blob) > symoff + 128
            snapshot_hash = blob[symoff + 20:symoff + 52].tobytes().decode()
            flag_data = blob[symoff + 52:symoff + 52 + 256].tobytes()
            flags = flag_data[:flag_data.index(b'\0')].decode().strip().split(' ')
            return snapshot_hash, flags

        elf = ELFFile(f)
        # find "_kDartVmSnapshotData" symbol
        dynsym = elf.get_section_by_name('.dynsym')
        sym = dynsym.get_symbol_by_name('_kDartVmSnapshotData')[0]
        #section = elf.get_section(sym['st_shndx'])
        assert sym['st_size'] > 128
        f.seek(sym['st_value']+20)
        snapshot_hash = f.read(32).decode()
        data = f.read(256) # should be enough
        flags = data[:data.index(b'\0')].decode().strip().split(' ')
    
    return snapshot_hash, flags

def extract_libflutter_info(libflutter_file, arch: str = None):
    with open(libflutter_file, 'rb') as f:
        magic = f.read(4)
        f.seek(0)
        if magic in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf', b'\xcf\xfa\xed\xfe'):
            data = f.read()
            _, _, sections, arch, os_name = _parse_macho(data, arch or 'arm64')
            search_data = b''.join(sections.values()) if sections else data

            sha_hashes = re.findall(b'\x00([a-f\\d]{40})(?=\x00)', search_data)
            engine_ids = [h.decode() for h in sha_hashes]
            assert len(engine_ids) >= 1, 'Cannot find Flutter engine hash in Mach-O'

            m = re.search(br'\x00([\d\w\.-]+) \((stable|beta|dev)\)', search_data)
            dart_version = None if m is None else m.group(1).decode()
            return engine_ids, dart_version, arch, os_name

        elf = ELFFile(f)
        if elf.header.e_machine == 'EM_AARCH64': # 183
            arch = 'arm64'
        elif elf.header.e_machine == 'EM_IA_64': # 50
            arch = 'x64'
        else:
            assert False, f"Unsupport architecture: {elf.header.e_machine}"

        section = elf.get_section_by_name('.rodata')
        data = section.data()
        
        sha_hashes = re.findall(b'\x00([a-f\\d]{40})(?=\x00)', data)
        #print(sha_hashes)
        # all possible engine ids
        engine_ids = [ h.decode() for h in sha_hashes ]
        assert len(engine_ids) == 2, f'found hashes {", ".join(engine_ids)}'
        
        # beta/dev version of flutter might not use stable dart version (we can get dart version from sdk with found engine_id)
        # support stable, beta and dev channels
        m = re.search(br'\x00([\d\w\.-]+) \((stable|beta|dev)\)', data)
        if m is None:
            dart_version = None
        else:
            dart_version = m.group(1).decode()
        
    return engine_ids, dart_version, arch, 'android'

def get_dart_sdk_url_size(engine_ids):
    #url = f'https://storage.googleapis.com/dart-archive/channels/stable/release/3.0.3/sdk/dartsdk-windows-x64-release.zip'
    for engine_id in engine_ids:
        url = f'https://storage.googleapis.com/flutter_infra_release/flutter/{engine_id}/dart-sdk-windows-x64.zip'
        resp = requests.head(url)
        if resp.status_code == 200:
           sdk_size = int(resp.headers['Content-Length'])
           return engine_id, url, sdk_size
    
    return None, None, None

def get_dart_commit(url):
    # in downloaded zip
    # * dart-sdk/revision - the dart commit id of https://github.com/dart-lang/sdk/
    # * dart-sdk/version  - the dart version
    # revision and version zip file records should be in first 4096 bytes
    # using stream in case a server does not support range
    commit_id = None
    dart_version = None
    fp = None
    with requests.get(url, headers={"Range": "bytes=0-4096"}, stream=True) as r:
        if r.status_code // 10 == 20:
            x = next(r.iter_content(chunk_size=4096))
            fp = io.BytesIO(x)
    
    if fp is not None:
        while fp.tell() < 4096-30 and (commit_id is None or dart_version is None):
            #sig, ver, flags, compression, filetime, filedate, crc, compressSize, uncompressSize, filenameLen, extraLen = unpack(fp, '<IHHHHHIIIHH')
            _, _, _, compMethod, _, _, _, compressSize, _, filenameLen, extraLen = unpack('<IHHHHHIIIHH', fp.read(30))
            filename = fp.read(filenameLen)
            #print(filename)
            if extraLen > 0:
                fp.seek(extraLen, io.SEEK_CUR)
            data = fp.read(compressSize)
            
            # expect compression method to be zipfile.ZIP_DEFLATED
            assert compMethod == zipfile.ZIP_DEFLATED, 'Unexpected compression method'
            if filename == b'dart-sdk/revision':
                commit_id = zlib.decompress(data, wbits=-zlib.MAX_WBITS).decode().strip()
            elif filename == b'dart-sdk/version':
                dart_version = zlib.decompress(data, wbits=-zlib.MAX_WBITS).decode().strip()
    
    # TODO: if no revision and version in first 4096 bytes, get the file location from the first zip dir entries at the end of file (less than 256KB)
    return commit_id, dart_version

def extract_dart_info(libapp_file: str, libflutter_file: str, arch: str = None):
    snapshot_hash, flags = extract_snapshot_hash_flags(libapp_file, arch)
    #print('snapshot hash', snapshot_hash)
    #print(flags)

    engine_ids, dart_version, arch, os_name = extract_libflutter_info(libflutter_file, arch)
    # print('possible engine ids', engine_ids)
    # print('dart version', dart_version)

    if dart_version is None:
        engine_id, sdk_url, sdk_size = get_dart_sdk_url_size(engine_ids)
        # print(engine_id)
        # print(sdk_url)
        # print(sdk_size)

        commit_id, dart_version = get_dart_commit(sdk_url)
        # print(commit_id)
        # print(dart_version)
        #assert dart_version == dart_version_sdk
    
    # TODO: os (android or ios) and architecture (arm64 or x64)
    return dart_version, snapshot_hash, flags, arch, os_name


if __name__ == "__main__":
    if len(sys.argv) >= 3:
        libapp_file = sys.argv[1]
        libflutter_file = sys.argv[2]
        arch = None if len(sys.argv) < 4 else sys.argv[3]
    else:
        libdir = sys.argv[1]
        libapp_file = os.path.join(libdir, 'libapp.so')
        libflutter_file = os.path.join(libdir, 'libflutter.so')
        arch = None

    print(extract_dart_info(libapp_file, libflutter_file, arch))
