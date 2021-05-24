cmake_minimum_required(VERSION 3.13)

# 絶対パス->相対パス変換
cmake_policy(SET CMP0076 NEW)
#cmake_policy(SET CMP0015 NEW)

####################
# options
####################
include(../cmake/EnableCcache.cmake)
include(../cmake/ConvertSrclistFunction.cmake)
include(../cmake/CfdCommonOption.cmake)
include(../cmake/CfdCommonSetting.cmake)

option(CFDCORE_SHARED "cfdcore force shared build (ON or OFF. default:OFF)" OFF)
option(CFDCORE_DEBUG "cfd debug mode (ON or OFF. default:OFF)" OFF)
option(CFDCORE_LOG_CONSOLE "output console log (ON or OFF. default:OFF)" OFF)
option(CFDCORE_LOG_LEVEL "output log level (trace/debug/info/warn. default:info)" "info")

if(CFDCORE_SHARED AND (WIN32 OR APPLE))
set(USE_CFDCORE_SHARED  TRUE)
else()
set(USE_CFDCORE_SHARED  FALSE)
endif()


####################
# common setting
####################
include(../cmake/CfdCoverage.cmake)


####################
# cfdcore
####################
project(cfdcore CXX)
# set(LIBRARY_PREFIX $<IF:$<PLATFORM_ID:Windows>,,lib>)
# set(LIBRARY_SUFFIX $<IF:$<PLATFORM_ID:Windows>,dll,$<IF:$<PLATFORM_ID:Darwin>,dylib,so>>)
set(LIBWALLY_LIBRARY wally)
set(UNIVALUE_LIBRARY univalue)

transform_makefile_srclist("Makefile.srclist" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.srclist.cmake")
include(${CMAKE_CURRENT_BINARY_DIR}/Makefile.srclist.cmake)
include(../cmake/Cpp11Setting.cmake)

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

if(NOT ENABLE_LOGGING)
set(CFDCORE_LOGGING_OPT "")
else()
set(CFDCORE_LOGGING_OPT  CFDCORE_LOGGING)
endif()

if(NOT CFDCORE_LOG_LEVEL)
set(CFDCORE_LOG_LEVEL_OPT "3")  # info
else()
if(CFDCORE_LOG_LEVEL STREQUAL "trace")
set(CFDCORE_LOG_LEVEL_OPT "1")  # trace
else()
if(CFDCORE_LOG_LEVEL STREQUAL "debug")
set(CFDCORE_LOG_LEVEL_OPT "2")  # debug
else()
if(CFDCORE_LOG_LEVEL STREQUAL "warn" or CFDCORE_LOG_LEVEL STREQUAL "warning")
set(CFDCORE_LOG_LEVEL_OPT "4")  # warn
else()
set(CFDCORE_LOG_LEVEL_OPT "3")  # info
endif()
endif()
endif()
endif()

find_package(wally  QUIET)
if((NOT wally_FOUND) OR (NOT ${wally_FOUND}))
set(LIBWALLY_LIBRARY wally)
set(UNIVALUE_LIBRARY univalue)

else()
message(STATUS "[wally_FOUND]=${wally_FOUND}")
message(STATUS "[wally_DIR]=${wally_DIR}")

set(LIBWALLY_LIBRARY wally)
set(UNIVALUE_LIBRARY univalue)
endif()

if(ENABLE_SHARED OR USE_CFDCORE_SHARED)
add_library(${PROJECT_NAME} SHARED)
else()
add_library(${PROJECT_NAME} STATIC)
endif()


if(NOT ENABLE_LOGGING)
target_sources(${PROJECT_NAME}
  PRIVATE
    ${CFDCORE_SOURCES}
    ${FMT_SOURCES}
)
else()
target_sources(${PROJECT_NAME}
  PRIVATE
    ${CFDCORE_SOURCES}
    ${FMT_SOURCES}
    ${QUILL_SOURCES}
)
endif()


target_compile_options(${PROJECT_NAME}
  PRIVATE
    $<IF:$<CXX_COMPILER_ID:MSVC>,
      /LD
      /source-charset:utf-8 /Wall
      /wd4061 /wd4244 /wd4251 /wd4365 /wd4464 /wd4514 /wd4571 /wd4574 /wd4623 /wd4625 /wd4626 /wd4710 /wd4711 /wd4774 /wd4820 /wd4946 /wd5026 /wd5027 /wd5039 /wd5045 /wd5052
      ${STACK_PROTECTOR_OPT},
      -Wall -Wextra ${PROFILE_ARCS_OPT} ${TEST_COVERAGE_OPT} ${EMSCRIPTEN_OPT}
    >
    $<$<BOOL:$<CXX_COMPILER_ID:GNU>>:${STACK_PROTECTOR_OPT}>
)
target_compile_definitions(${PROJECT_NAME}
  PRIVATE
    QUILL_FMT_EXTERNAL=1
    FMT_EXPORT=1
    CFD_CORE_BUILD=1
    WALLY_DISABLE_OP_CODE=1
    ${CFD_ELEMENTS_USE}
    ${ELEMENTS_COMP_OPT}
    ${CFDCORE_DEBUG_OPT}
    ${CFDCORE_LOG_CONSOLE_OPT}
    ${CFDCORE_LOGGING_OPT}
    CFDCORE_LOG_LEVEL=${CFDCORE_LOG_LEVEL_OPT}
)

if((NOT wally_FOUND) OR (NOT ${wally_FOUND}))
target_include_directories(${PROJECT_NAME}
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    .
    include
    univalue/include
    quill/include
)
target_link_directories(${PROJECT_NAME}
  PRIVATE
    ./
)
set(USE_INSTALLED_LIBRARY  FALSE)
else()
target_include_directories(${PROJECT_NAME}
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    .
    include
    univalue/include
    quill/include
    ${wally_DIR}/../include
)
target_link_directories(${PROJECT_NAME}
  PRIVATE
    ./
    ${wally_DIR}/../lib
)
set(USE_INSTALLED_LIBRARY  TRUE)
endif()

target_link_libraries(${PROJECT_NAME}
  PRIVATE $<$<BOOL:$<CXX_COMPILER_ID:GNU>>:-static-libgcc>
  PRIVATE $<$<BOOL:$<CXX_COMPILER_ID:GNU>>:-static-libstdc++>
  PRIVATE $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:pthread>
  PRIVATE
    ${LIBWALLY_LIBRARY}
    ${UNIVALUE_LIBRARY}
    ${GCOV_LIBRARY}
)


if(USE_INSTALLED_LIBRARY)
set(INSTALLED_LIBRARY_DIR  ${wally_DIR}/../lib)
if(ENABLE_SHARED)
set(LIB_PREFIX  ${CMAKE_SHARED_LIBRARY_PREFIX})
set(LIB_SUFFIX  ${CMAKE_SHARED_LIBRARY_SUFFIX})
else()
set(LIB_PREFIX  ${CMAKE_STATIC_LIBRARY_PREFIX})
set(LIB_SUFFIX  ${CMAKE_STATIC_LIBRARY_SUFFIX})
endif()

set(LIBWALLY_LIB_PATH  ${INSTALLED_LIBRARY_DIR}/${LIB_PREFIX}wally${LIB_SUFFIX})
set(UNIVALUE_LIB_PATH  ${INSTALLED_LIBRARY_DIR}/${LIB_PREFIX}univalue${LIB_SUFFIX})

add_custom_command(
    TARGET ${PROJECT_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy  ${LIBWALLY_LIB_PATH} ${CFD_OBJ_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy  ${UNIVALUE_LIB_PATH} ${CFD_OBJ_BINARY_DIR}
)

if(NOT ENABLE_SHARED)
set(LIB_PREFIX  ${CMAKE_SHARED_LIBRARY_PREFIX})
set(LIB_SUFFIX  ${CMAKE_SHARED_LIBRARY_SUFFIX})
set(LIBWALLY_LIB_PATH  ${INSTALLED_LIBRARY_DIR}/${LIB_PREFIX}wally${LIB_SUFFIX})
set(UNIVALUE_LIB_PATH  ${INSTALLED_LIBRARY_DIR}/${LIB_PREFIX}univalue${LIB_SUFFIX})

if(EXISTS ${CFDCORE_LIB_PATH})
add_custom_command(
    TARGET ${PROJECT_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy  ${LIBWALLY_LIB_PATH} ${CFD_OBJ_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy  ${UNIVALUE_LIB_PATH} ${CFD_OBJ_BINARY_DIR}
)
endif(EXISTS ${CFDCORE_LIB_PATH})
endif(NOT ENABLE_SHARED)
endif()   # USE_INSTALLED_LIBRARY


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
set(CMAKE_INCLUDE_CURRENT_DIR_IN_INTERFACE ON) 

install(TARGETS       ${PROJECT_NAME}
        EXPORT        ${PROJECT_NAME}-export
        ARCHIVE       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        OBJECTS       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT ${PROJECT_NAME}-export
        FILE ${PROJECT_NAME}-config.cmake
        DESTINATION "cmake/"
        EXPORT_LINK_INTERFACE_LIBRARIES)

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../include/cfdcore"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        FILES_MATCHING PATTERN "*.h")

if(MSVC)
install(DIRECTORY "${CFD_OBJ_BINARY_DIR}/"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        FILES_MATCHING PATTERN "*.exp")
endif()

#export(TARGETS ${PROJECT_NAME}
#       APPEND FILE ${PROJECT_BINARY_DIR}/${PROJECT_NAME}-config.cmake)
