# Crypto Finance Development Kit Core (CFD-CORE)

Core library for cfd libraries.

## Overview

This library is development kit for crypto finance application.
Useful when developing applications for cryptocurrencies.

### Target Network

- Bitcoin
- Liquid Network

### Support function by cfd-core

- Bitcoin
  - Bitcoin Script (builder, viewer)
  - Transaction
  - PSBT (v0)
  - ECDSA Pubkey/Privkey (TweakAdd/Mul, Negate, Sign, Verify)
  - BIP32, BIP39
  - Output Descriptor (contains miniscript parser)
  - Schnorr/Taproot
  - Bitcoin Address (Segwit-v0, Segwit-v1, P2PKH/P2SH)
- Liquid Network
  - Confidential Transaction
    - Blind, Unblind
    - Issuance, Reissuance
    - PegIn, PegOut
  - Confidential Address

### Libraries for each language

- C++ : cfd-core
  - Core library. Definition base class.
- C/C++ : cfd
  - Extend the cfd-core library. Defines the C language API and extension classes.
- Libraries to link cfd library:
  - JavaScript : cfd-js
  - WebAssembly : cfd-js-wasm
  - Python : cfd-python
  - C# : cfd-csharp
  - Go : cfd-go
  - Rust : cfd-rust

## Dependencies

- C/C++ Compiler
  - can compile c++11 or upper (default is c++11. use STD_CPP_VERSION option)
- CMake (3.14.3 or higher)
- When using npm scripts and cmake-js
  - node.js (stable version)
  - Python 3.x
    - for building libwally-core js wrapper

### Windows

download and install files.

- [CMake](https://cmake.org/) (3.14.3 or higher)
- Compiler or development environment (One of the following)
  - MSVC
    - [Visual Studio](https://visualstudio.microsoft.com/downloads/) (Verified version is 2017 or higher)
    - [Build Tools for Visual Studio](https://visualstudio.microsoft.com/downloads/) (2017 or higher)
    - (Using only) [msvc redistribution package](https://support.microsoft.com/help/2977003/the-latest-supported-visual-c-downloads)
  - Clang
    - [LLVM](https://releases.llvm.org/download.html) (Requires MSVC or MinGW)
  - [MinGW w64](http://mingw-w64.org/)
  - [MSYS2](https://www.msys2.org/)
    - Use MinGW
  - other
    - I have not confirmed it, but I think that it can be built if it supports c++11 and cmake.

### MacOS

- [Homebrew](https://brew.sh/)

```Shell
# xcode cli tools
xcode-select --install

# install dependencies using Homebrew
brew install cmake python node
```

### Linux(Ubuntu)

```Shell
# install dependencies using APT package Manager
apt-get install -y build-essential cmake python nodejs
```

cmake version 3.14.2 or lower, download from website and install cmake.
(<https://cmake.org/download/>)

---

## Build

### Using cmake-js

(If you want to install, [see the installation](#Using-cmake-js-install). Introduces build and install command.)

When using the cmake-js package and npm script, the options for compilation are already set.

```Shell
npm install
npm run cmake_all
```

### Use CMake

```Shell
# recommend out of source build
mkdir build && cd $_
# configure & build
cmake .. (CMake options)
make
```

``` (windows) command prompt example
cmake -S . -B build  -G "Visual Studio 16 2019"
cmake -D ENABLE_SHARED=1 -DCMAKE_BUILD_TYPE=Release --build build
cmake --build build
```

### CMake options

- `-DENABLE_ELEMENTS`: Enable functionalies for elements sidechain. [ON/OFF] (default:ON)
- `-DENABLE_SHARED`: Enable building a shared library. [ON/OFF] (default:OFF)
- `-DENABLE_TESTS`: Enable building a testing codes. If enables this option, builds testing framework submodules(google test) automatically. [ON/OFF] (default:ON)
- `-DTARGET_RPATH=xxxxx;yyyyy`: Set rpath (Linux, MacOS). Separator is ';'.
- `-DCMAKE_BUILD_TYPE=Release`: Enable release build.
- `-DCMAKE_BUILD_TYPE=Debug`: Enable debug build.
- `-DSTD_CPP_VERSION=xx`: Set the C++ version. [11,14,17,20] (default:11)
- `-DCFDCORE_DEBUG=on`: Enable cfd debug mode and loggings log files. [ON/OFF] (default:OFF)
  - Enable debug mode is need `STD_CPP_VERSION` upper 14.
- `-DCFDCORE_LOG_LEVEL=xxxx`: Set log level. [trace/debug/info/warn] (default:info)
- `-DCFDCORE_LOG_CONSOLE=on`: Enable cfd loggings console output mode. [ON/OFF] (default:OFF)

---

## install / uninstall

On Linux or MacOS, can use install / uninstall.

### install (after build)

install for `/usr/local/lib`.

#### Using cmake-js install

When using the cmake-js package and npm script, the options for compilation are already set.

```Shell
npm cmake_make_install
(Enter the password when prompted to use the sudo command.)
```

cmake version is 3.15 or higher:

```Shell
npm cmake_install
(Enter the password when prompted to use the sudo command.)
```

#### Using CMake install

```Shell
cd build && sudo make install

(Using ninja)
cd build && sudo ninja install
```

cmake version is 3.15 or higher: `cmake --install build`

### uninstall

```Shell
(uninstall by using makefile)
cd build && sudo make uninstall

(uninstall by using ninja)
cd build && sudo ninja uninstall

(uninstall by using script)
sudo ./tools/cleanup_install_files.sh
```

---

## Test and Example

### Test

```Shell
npm run ctest
```

### Example

- Not Implemented yet

---

## Information for developers

### using library

- [libwally-core](https://github.com/cryptogarageinc/libwally-core/tree/cfd-develop) (forked from [ElementsProject/libwally-core](https://github.com/ElementsProject/libwally-core))
  - [secp256k1-zkp](https://github.com/cryptogarageinc/secp256k1-zkp/tree/cfd-develop) (forked from [ElementsProject/secp256k1-zkp](https://github.com/ElementsProject/secp256k1-zkp))
- [univalue](https://github.com/jgarzik/univalue) (for JSON encoding and decoding)
- logger
  - [fmtlib](https://github.com/fmtlib/fmt) (for logging format tool)
  - [quill](https://github.com/odygrd/quill) (for logging)

### formatter

- clang-format (using v10.0.0)

### linter

- cpplint (customize from [google/styleguide/cpplint](https://github.com/google/styleguide/tree/gh-pages/cpplint))

### document tool

- doxygen & graphviz

### support compilers

- Visual Studio (2017 or higher)
- Clang (7.x or higher)
- GCC (contains MinGW) (5.x or higher)

### code coverage

- lcov
  - Collecting coverage only on Linux.
    - It is generated unnecessary constructors and destructors on MacOS. So it is not suitable for collecting function coverage.
    - It may be possible to run it on windows, but I have not tried it.

---

## Note

### Git connection

Git repository connections default to HTTPS.
However, depending on the connection settings of GitHub, you may only be able to connect via SSH.
As a countermeasure, forcibly establish SSH connection by setting `CFD_CMAKE_GIT_SSH=1` in the environment variable.

- Windows: (On the command line. Or set from the system setting screen.)

```Bat
set CFD_CMAKE_GIT_SSH=1
```

- MacOS & Linux(Ubuntu):

```Shell
export CFD_CMAKE_GIT_SSH=1
```

### Ignore git update for CMake External Project

Depending on your git environment, you may get the following error when checking out external:

```Shell
  Performing update step for 'libwally-core-download'
  Current branch cmake_build is up to date.
  No stash entries found.
  No stash entries found.
  No stash entries found.
  CMake Error at /workspace/cfd-core/build/external/libwally-core/download/libwally-core-download-prefix/tmp/libwally-core-download-gitupdate.cmake:133 (message):


    Failed to unstash changes in:
    '/workspace/cfd-core/external/libwally-core/'.

    You will have to resolve the conflicts manually
```

This phenomenon is due to the `git update` related command.
Please set an environment variable that skips update processing.

- Windows: (On the command line. Or set from the system setting screen.)

```Bat
set CFD_CMAKE_GIT_SKIP_UPDATE=1
```

- MacOS & Linux(Ubuntu):

```Shell
export CFD_CMAKE_GIT_SKIP_UPDATE=1
```
