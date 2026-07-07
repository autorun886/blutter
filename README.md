# B(l)utter

Flutter application reverse engineering tool by compiling a matching Dart AOT
runtime and using it to inspect a target `libapp` snapshot.

通过编译与目标应用匹配的 Dart AOT Runtime，读取并还原 Flutter AOT
快照中的 Dart 对象、函数、结构和 IDA 辅助信息。

## Supported Targets / 支持目标

This fork supports:

- Android Flutter AOT: `.apk`, `lib/arm64-v8a`, or a directory containing
  `libapp.so` and `libflutter.so`
- macOS Flutter AOT: `.app`, `App.framework`, or `App.framework/App`
- fat Mach-O inputs with explicit `--arch arm64` or `--arch x64`
- IDA script generation for Dart function names, Dart structures, object pool
  metadata, and annotated assembly

当前分支支持：

- Android Flutter AOT：`.apk`、`lib/arm64-v8a`，或同时包含 `libapp.so` 和
  `libflutter.so` 的目录
- macOS Flutter AOT：`.app`、`App.framework`，或 `App.framework/App`
- fat Mach-O，通过 `--arch arm64` 或 `--arch x64` 显式选择架构 slice
- 生成 IDA 脚本，用于恢复 Dart 函数名、Dart 结构、ObjectPool 信息和带注释汇编

Recent Dart versions are supported best. This branch has been validated with a
macOS Flutter app using Dart `3.9.2`, arm64, macOS, no-compressed-pointers.

较新的 Dart 版本支持效果最好。当前分支已用 Dart `3.9.2`、macOS、arm64、
no-compressed-pointers 的 Flutter 应用验证。

## Requirements / 环境要求

Blutter uses C++20 and builds a static Dart VM for the target snapshot. Use a
recent compiler and CMake/Ninja.

Blutter 使用 C++20，并会为目标快照编译静态 Dart VM。请使用较新的编译器、
CMake 和 Ninja。

### macOS

Install Xcode command line tools and dependencies:

安装 Xcode Command Line Tools 和依赖：

```sh
brew install cmake ninja pkg-config icu4c capstone
python3 -m pip install pyelftools requests
```

If your network requires a proxy, configure it before the first run because Dart
source checkout and build metadata may be downloaded.

如果网络需要代理，请在首次运行前自行配置。首次运行可能会下载 Dart 源码和构建元数据。

### Debian/Ubuntu

Use a distribution that provides a compiler with complete C++20 formatting
support, such as GCC 13 or newer:

请使用自带完整 C++20 formatting 支持的发行版，例如 GCC 13 或更新版本：

```sh
sudo apt install python3-pyelftools python3-requests git cmake ninja-build \
  build-essential pkg-config libicu-dev libcapstone-dev
```

### Windows

Install Git, Python 3, and Visual Studio with:

安装 Git、Python 3 和 Visual Studio，并勾选：

- Desktop development with C++
- C++ CMake tools

Initialize third-party libraries:

初始化第三方依赖：

```bat
python scripts\init_env_win.py
```

Run Blutter from an x64 Native Tools Command Prompt.

请在 x64 Native Tools Command Prompt 中运行 Blutter。

## Usage / 用法

The normal entry point is `blutter.py`:

常规入口是 `blutter.py`：

```sh
python3 blutter.py <input> <outdir> [options]
```

Blutter detects the Dart version, snapshot hash, target OS, architecture, and
compressed-pointer mode from the Flutter app. If the matching Dart VM package or
Blutter executable does not exist yet, it builds them automatically.

Blutter 会从 Flutter 应用中检测 Dart 版本、snapshot hash、目标系统、架构以及
compressed-pointers 模式。如果本地还没有匹配的 Dart VM 包或 Blutter 可执行文件，
会自动编译。

### Android APK

APK extraction currently supports Android arm64:

APK 自动解包目前支持 Android arm64：

```sh
python3 blutter.py path/to/app.apk out/android_app
```

You can also pass the extracted Android library directory:

也可以传入已解包的 Android so 目录：

```sh
python3 blutter.py path/to/lib/arm64-v8a out/android_app
```

The directory must contain `libapp.so` and `libflutter.so`.

该目录必须同时包含 `libapp.so` 和 `libflutter.so`。

### macOS App

For a macOS `.app`, pass the app bundle and select the architecture slice:

分析 macOS `.app` 时，传入 app bundle，并显式选择架构 slice：

```sh
python3 blutter.py path/to/App.app out/macos_arm64 --arch arm64
```

For Intel/x64 analysis:

分析 Intel/x64 slice：

```sh
python3 blutter.py path/to/App.app out/macos_x64 --arch x64
```

You can also pass:

也可以传入：

- `Contents/Frameworks/App.framework`
- `Contents/Frameworks/App.framework/App`
- a directory containing `App.framework` and `FlutterMacOS.framework`
- 同时包含 `App.framework` 和 `FlutterMacOS.framework` 的目录

For fat Mach-O binaries, always set `--arch` so the selected slice matches the
IDA database you will annotate.

对于 fat Mach-O，必须设置 `--arch`，并确保它与后续 IDA 打开的架构 slice 一致。

### Rebuild / 重新编译

Force regeneration of the Blutter executable for the detected Dart runtime:

强制重新生成当前 Dart runtime 对应的 Blutter 可执行文件：

```sh
python3 blutter.py path/to/App.app out/macos_arm64 --arch arm64 --rebuild
```

### Disable Code Analysis / 禁用代码分析

Use `--no-analysis` when you only need Dart objects, function names, Frida
templates, and IDA naming scripts, or when the architecture-specific analyzer is
not mature enough for a target:

如果只需要 Dart 对象、函数名、Frida 模板和 IDA 命名脚本，或者当前架构的代码分析器
对目标不够稳定，可以使用 `--no-analysis`：

```sh
python3 blutter.py path/to/App.app out/macos_x64 --arch x64 --no-analysis
```

x64 currently uses this path most reliably. arm64 can run the code-analysis path,
but recent Dart versions may still print non-fatal `Analysis error` messages for
some newer code patterns.

当前 x64 最稳定的方式是配合 `--no-analysis` 使用。arm64 可以运行完整代码分析路径，
但较新的 Dart 版本可能会对部分新代码模式打印非致命的 `Analysis error`。

### Run Without Flutter Engine Metadata / 无 Flutter 引擎元数据运行

If `libflutter` or `FlutterMacOS` is unavailable, provide the Dart target
manually:

如果没有 `libflutter` 或 `FlutterMacOS`，可以手动指定 Dart 目标：

```sh
python3 blutter.py path/to/libapp.so out/manual \
  --dart-version 3.9.2_android_arm64
```

For macOS:

macOS 示例：

```sh
python3 blutter.py path/to/App.framework/App out/manual \
  --dart-version 3.9.2_macos_arm64 --arch arm64
```

## IDA Workflow / IDA 工作流

Blutter writes an IDA script to:

Blutter 会生成 IDA 脚本：

```text
<outdir>/ida_script/addNames.py
```

Open the same binary slice in IDA that was selected with `--arch`, then run the
script with IDAPython.

在 IDA 中打开与 `--arch` 相同的二进制 slice，然后用 IDAPython 运行该脚本。

For a fat macOS app, it is often clearer to thin the slice first:

对于 macOS fat Mach-O，推荐先抽出单架构文件：

```sh
lipo path/to/App.framework/App -thin arm64 -output App_arm64
```

Then open `App_arm64` in IDA and run:

然后在 IDA 中打开 `App_arm64` 并运行：

```python
exec(open("/absolute/path/to/out/ida_script/addNames.py").read())
```

The script creates function names such as:

脚本会生成类似下面的函数名：

```text
kdwrite_app$core$utils$splash_utils_SplashUtils::close_2e2680
kdwrite_app$app_App::routeObserver_20db00
kdwrite_app$features$editor$modules$find_replace$find_bar_FindReplaceBar::build_3ef91c
```

By default, large object-pool member comments are omitted from `addNames.py` so
the script stays fast and works well through IDA MCP or other automated runners.
To include those comments, regenerate the output with:

默认情况下，`addNames.py` 不写入大量 ObjectPool 成员注释，这样脚本更快，也更适合
IDA MCP 等自动化环境。如果需要包含这些注释，重新生成时设置：

```sh
BLUTTER_IDA_OBJECT_POOL_COMMENTS=1 \
python3 blutter.py path/to/App.app out/macos_arm64 --arch arm64 --rebuild
```

## Output Files / 输出文件

- `asm/`: annotated application assembly grouped by Dart library path
- `asm/`：按 Dart library 路径组织的带注释汇编
- `blutter_frida.js`: Frida script template for the target application
- `blutter_frida.js`：目标应用的 Frida 脚本模板
- `objs.txt`: complete nested dump of objects reachable from the object pool
- `objs.txt`：从 ObjectPool 可达对象的完整嵌套 dump
- `pp.txt`: object pool entries and recovered Dart metadata
- `pp.txt`：ObjectPool 条目和恢复出的 Dart 元数据
- `ida_script/addNames.py`: IDAPython script for function names and structures
- `ida_script/addNames.py`：用于恢复函数名和结构体的 IDAPython 脚本
- `ida_script/ida_dart_struct.h`: C declarations imported by the IDA script
- `ida_script/ida_dart_struct.h`：IDA 脚本导入的 C 结构声明

## Project Layout / 项目结构

- `bin/`: built Blutter executables, named by Dart version, OS, arch, pointer
  compression, and analysis mode
- `bin/`：编译好的 Blutter 可执行文件，名称包含 Dart 版本、系统、架构、
  pointer compression 和 analysis 模式
- `blutter/`: C++ source code
- `blutter/`：C++ 源码
- `build/`: CMake/Ninja build directories; safe to delete when not building
- `build/`：CMake/Ninja 构建目录；不构建时可以删除
- `dartsdk/`: checked-out Dart runtime sources
- `dartsdk/`：检出的 Dart Runtime 源码
- `external/`: Windows third-party dependency cache
- `external/`：Windows 第三方依赖缓存
- `packages/`: built Dart VM static libraries and CMake package metadata
- `packages/`：编译出的 Dart VM 静态库和 CMake 包元数据
- `scripts/`: CMake and Python helpers for Dart VM fetch/build
- `scripts/`：用于获取和编译 Dart VM 的 CMake/Python 辅助脚本

## Development / 开发

Generate a Visual Studio solution:

生成 Visual Studio solution：

```bat
python blutter.py path\to\lib\arm64-v8a build\vs --vs-sln
```

For normal CMake/Ninja development, run Blutter with `--rebuild` after changing
C++ sources.

普通 CMake/Ninja 开发时，修改 C++ 源码后用 `--rebuild` 重新运行。

## Current Limitations / 当前限制

- APK extraction currently supports Android arm64 only.
- APK 自动解包目前只支持 Android arm64。
- IPA extraction is not implemented.
- 尚未实现 IPA 自动解包。
- macOS fat binaries require explicit `--arch` selection.
- macOS fat Mach-O 必须显式选择 `--arch`。
- IDA import must use the same architecture slice as Blutter.
- IDA 导入必须使用与 Blutter 相同的架构 slice。
- x64 code analysis is best used with `--no-analysis`.
- x64 代码分析建议使用 `--no-analysis`。
- arm64 code analysis works, but Dart 3.9+ no-compressed-pointer apps may still
  emit non-fatal analysis warnings for some write-barrier and field-table
  patterns.
- arm64 代码分析可以运行，但 Dart 3.9+ no-compressed-pointer 应用中，部分
  write-barrier 和 field-table 模式仍可能产生非致命分析警告。
- Obfuscated Flutter apps can still miss functions or produce less readable
  names.
- 混淆后的 Flutter 应用仍可能漏函数，或生成可读性较差的名称。
