# Crypto Finance Development Kit Core (CFD-CORE)

core moduels for cfd libraries

<!-- TODO: Write Summary and Overview

## Overview

-->

## Dependencies

- C/C++ Compiler
  - can compile c++11
- CMake (3.14.3 or higher)
- Python 3.x
- node.js (stable version)

### Windows

download and install files.
- Visual Studio (Verified version is 2017 or higher)
  - use for compiler only
- Visual Studio Build Tools (2017 or higher)
- cmake (3.14.3 or higher)
- Python 3.x

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
(https://cmake.org/download/)

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

**CMake options**

- `-DENABLE_ELEMENTS`: Enable functionalies for elements sidechain. [ON/OFF] (default:ON)
- `-DENABLE_SHARED`: Enable building a shared library. [ON/OFF] (default:OFF)
- `-DENABLE_TESTS`: Enable building a testing codes. If enables this option, builds testing framework submodules(google test) automatically. [ON/OFF] (default:ON)
- `-DTARGET_RPATH=xxxxx;yyyyy`: Set rpath (Linux, MacOS). Separator is ';'.
- `-DCMAKE_BUILD_TYPE=Release`: Enable release build.
- `-DCMAKE_BUILD_TYPE=Debug`: Enable debug build.
- `-DCFDCORE_DEBUG=on`: Enable cfd debug mode and loggings log files. [ON/OFF] (default:OFF)

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
cd build && sudo make uninstall

(Using ninja)
cd build && sudo ninja uninstall
```

---

## Example

### Test

```Shell
npm run ctest
```

### Example

- Not Implemented yet

---

## Information for developers

### using library

- libwally-core (forked from [ElementsProject](https://github.com/ElementsProject/libwally-core))
- univalue
- googletest (for testing)

### formatter

- clang-format (using v10.0.0)

### linter

- cpplint

### document tool

- doxygen & graphviz

---

## Note

### Git connection:

Git repository connections default to HTTPS.
However, depending on the connection settings of GitHub, you may only be able to connect via SSH.
As a countermeasure, forcibly establish SSH connection by setting `CFD_CMAKE_GIT_SSH=1` in the environment variable.

- Windows: (On the command line. Or set from the system setting screen.)
```
set CFD_CMAKE_GIT_SSH=1
```

- MacOS & Linux(Ubuntu):
```
export CFD_CMAKE_GIT_SSH=1
```

### Ignore git update for CMake External Project:

Depending on your git environment, you may get the following error when checking out external:
```
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
```
set CFD_CMAKE_GIT_SKIP_UPDATE=1
```

- MacOS & Linux(Ubuntu):
```
export CFD_CMAKE_GIT_SKIP_UPDATE=1
```
