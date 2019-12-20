cmake_minimum_required(VERSION 3.13)

# 絶対パス->相対パス変換
cmake_policy(SET CMP0076 NEW)
#cmake_policy(SET CMP0015 NEW)

####################
# options
####################
option(CFDCORE_SHARED "force shared build (ON or OFF. default:OFF)" OFF)
if(CMAKE_JS_INC)
option(ENABLE_SHARED "enable shared library (ON or OFF. default:ON)" ON)
else()
option(ENABLE_SHARED "enable shared library (ON or OFF. default:OFF)" OFF)
endif()
# use "cmake -DCMAKE_BUILD_TYPE=Debug" or "cmake-js -D"
# option(ENABLE_DEBUG "enable debugging (ON or OFF. default:OFF)" OFF)
option(ENABLE_ELEMENTS "enable elements code (ON or OFF. default:ON)" ON)
option(ENABLE_BITCOIN  "enable bitcoin code (ON or OFF. default:ON)" ON)

if(NOT WIN32)
#option(TARGET_RPATH "target rpath list (separator is ';') (default:)" "")
set(TARGET_RPATH "" CACHE STRING "target rpath list (separator is ';') (default:)")
option(ENABLE_COVERAGE "enable code coverage (ON or OFF. default:OFF)" OFF)
else()
set(TARGET_RPATH "")
set(ENABLE_COVERAGE FALSE)
endif()

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
set(ENABLE_DEBUG  TRUE)
set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS $<$<CONFIG:Debug>:DEBUGBUILD>)
if(ENABLE_COVERAGE)
set(STACK_PROTECTOR_OPT  "")
else()
set(STACK_PROTECTOR_OPT  $<IF:$<CXX_COMPILER_ID:MSVC>,/GS,-fstack-check -fstack-protector>)
endif()
else()
set(ENABLE_DEBUG  FALSE)
set(STACK_PROTECTOR_OPT  "")
endif() # CMAKE_BUILD_TYPE

if(CFDCORE_SHARED AND (WIN32 OR APPLE))
set(USE_CFDCORE_SHARED  TRUE)
else()
set(USE_CFDCORE_SHARED  FALSE)
endif()

####################
# common setting
####################
set(WORK_WINDOWS_BINARY_DIR_NAME  $<IF:$<CONFIG:Debug>,Debug,Release>)
if(NOT CFD_OBJ_BINARY_DIR)
set(CFD_OBJ_BINARY_DIR   ${CMAKE_BINARY_DIR}/${WORK_WINDOWS_BINARY_DIR_NAME})
set(CFD_ROOT_BINARY_DIR  ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY  ${CFD_OBJ_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY  ${CFD_OBJ_BINARY_DIR}) # for linux
endif()

if(NOT ENABLE_BITCOIN)
set(CFD_BITCOIN_USE   CFD_DISABLE_BITCOIN)
else()
set(CFD_BITCOIN_USE   "")
endif()

if(NOT ENABLE_ELEMENTS)
set(ELEMENTS_COMP_OPT "")
set(CFD_ELEMENTS_USE   CFD_DISABLE_ELEMENTS)
else()
set(ELEMENTS_COMP_OPT  BUILD_ELEMENTS)
set(CFD_ELEMENTS_USE   "")
endif()

if(NOT WIN32)
if(APPLE)
set(CMAKE_MACOSX_RPATH 1)
endif()
set(CMAKE_SKIP_BUILD_RPATH  FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

if(TARGET_RPATH)
set(CMAKE_INSTALL_RPATH "${TARGET_RPATH};./;@rpath")
else()
set(CMAKE_INSTALL_RPATH "./;@rpath")
endif()
endif()

if(ENABLE_DEBUG AND ENABLE_COVERAGE)
set(COLLECT_COVERAGE ON)
set(PROFILE_ARCS_OPT -fprofile-arcs)
set(TEST_COVERAGE_OPT -ftest-coverage)
set(GCOV_LIBRARY gcov)
set(COVERAGE 1)
else()
set(PROFILE_ARCS_OPT  "")
set(TEST_COVERAGE_OPT "")
set(GCOV_LIBRARY  "")
endif()


####################
# cfdcore setting
####################
transform_makefile_srclist("Makefile.srclist" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.srclist.cmake")
include(${CMAKE_CURRENT_BINARY_DIR}/Makefile.srclist.cmake)

if(NOT CFDCORE_DEBUG)
set(CFDCORE_DEBUG_OPT "")
else()
set(CFDCORE_DEBUG_OPT  CFDCORE_DEBUG)
endif()

if(NOT CFDCORE_LOG_CONSOLE)
set(CFDCORE_LOG_CONSOLE_OPT "")
else()
set(CFDCORE_LOG_CONSOLE_OPT  CFDCORE_LOG_CONSOLE)
endif()

####################
# cfdcore
####################
project(cfdcore CXX)
# set(LIBRARY_PREFIX $<IF:$<PLATFORM_ID:Windows>,,lib>)
# set(LIBRARY_SUFFIX $<IF:$<PLATFORM_ID:Windows>,dll,$<IF:$<PLATFORM_ID:Darwin>,dylib,so>>)
set(LIBWALLY_LIBRARY wally)
set(UNIVALUE_LIBRARY univalue)

if(MSVC)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Od /Zi")
else()
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -ggdb")
endif()

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(ENABLE_SHARED OR USE_CFDCORE_SHARED)
add_library(${PROJECT_NAME} SHARED)
else()
add_library(${PROJECT_NAME} STATIC)
endif()
target_sources(${PROJECT_NAME}
  PRIVATE
    ${CFDCORE_SOURCES}
)

target_compile_options(${PROJECT_NAME}
  PRIVATE
    $<IF:$<CXX_COMPILER_ID:MSVC>,
      /LD
      /source-charset:utf-8 /Wall
      /wd4061 /wd4244 /wd4251 /wd4365 /wd4464 /wd4514 /wd4571 /wd4574 /wd4623 /wd4625 /wd4626 /wd4710 /wd4711 /wd4774 /wd4820 /wd4946 /wd5026 /wd5027 /wd5039 /wd5045 /wd5052
      ${STACK_PROTECTOR_OPT},
      -Wall -Wextra ${PROFILE_ARCS_OPT} ${TEST_COVERAGE_OPT}
    >
    $<$<BOOL:$<CXX_COMPILER_ID:GNU>>:${STACK_PROTECTOR_OPT}>
)
target_compile_definitions(${PROJECT_NAME}
  PRIVATE
    CFD_CORE_BUILD=1
    ${CFD_BITCOIN_USE}
    ${CFD_ELEMENTS_USE}
    ${ELEMENTS_COMP_OPT}
    ${CFDCORE_DEBUG_OPT}
    ${CFDCORE_LOG_CONSOLE_OPT}
)

target_include_directories(${PROJECT_NAME}
  PUBLIC
    ../include
  PRIVATE
    .
    include
    univalue/include
)

target_link_directories(${PROJECT_NAME}
  PRIVATE
    ./
)

target_link_libraries(${PROJECT_NAME}
  PRIVATE $<$<BOOL:$<CXX_COMPILER_ID:GNU>>:-static-libgcc>
  PRIVATE $<$<BOOL:$<CXX_COMPILER_ID:GNU>>:-static-libstdc++>
  PRIVATE $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:pthread>
  PRIVATE
    ${LIBWALLY_LIBRARY}
    ${UNIVALUE_LIBRARY}
    ${GCOV_LIBRARY}
)


####################
# coverage
####################
if(ENABLE_DEBUG AND ENABLE_COVERAGE)
add_custom_target(
  lcov_cfdcore1 ${CMAKE_COMMAND} -E make_directory ${CFD_ROOT_BINARY_DIR}/lcov_cfdcore_output
  COMMAND lcov -c -d . -o cfdcore1.info
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/cfdcore.dir
)
#  COMMAND gcov -f -m *.gcda > console.log
add_custom_target(
  lcov_cfdcore lcov -e cfdcore1.info "*/cfdcore_*" -o cfdcore.info
  COMMAND genhtml -s --demangle-cpp -o ${CFD_ROOT_BINARY_DIR}/lcov_cfdcore_output cfdcore.info
  DEPENDS lcov_cfdcore1
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/cfdcore.dir
)
endif()
# lcov -c -d . -o cfdcore1.info
# lcov -e cfdcore1.info "*/cfdcore_*" -o cfdcore.info
# genhtml -s --demangle-cpp -o output cfdcore.info


####################
# install & export
####################
include(GNUInstallDirs)

install(TARGETS       ${PROJECT_NAME}
        EXPORT        ${PROJECT_NAME}-export
        ARCHIVE       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
# https://cmake.org/cmake/help/latest/command/install.html

export(TARGETS ${PROJECT_NAME}
       APPEND FILE ${PROJECT_BINARY_DIR}/${PROJECT_NAME}-export.cmake
       EXPORT_LINK_INTERFACE_LIBRARIES)

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../include/cfdcore"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        FILES_MATCHING PATTERN "*.h")
