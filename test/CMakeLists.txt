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

option(CFDCORE_SHARED "force shared build (ON or OFF. default:OFF)" OFF)

if(CFDCORE_SHARED AND (WIN32 OR APPLE))
set(USE_CFDCORE_SHARED  TRUE)
else()
set(USE_CFDCORE_SHARED  FALSE)
endif()


####################
# cfdcore test
####################
if(ENABLE_TESTS)
enable_testing()
include(CTest)
project(cfdcore_test CXX)

transform_makefile_srclist("Makefile.srclist" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.srclist.cmake")
include(${CMAKE_CURRENT_BINARY_DIR}/Makefile.srclist.cmake)
include(../cmake/Cpp11Setting.cmake)

find_package(wally  QUIET)

set(LIBWALLY_LIBRARY wally)
set(UNIVALUE_LIBRARY univalue)
set(CFDCORE_LIBRARY cfdcore)

if(WIN32 AND ENABLE_SHARED)
add_executable(${PROJECT_NAME} ${TEST_CFDCORE_SOURCES})
else()
add_executable(${PROJECT_NAME} ${TEST_CFDCORE_SOURCES} ${TEST_CFDCORE_STATIC_SOURCES})
endif()

target_compile_options(${PROJECT_NAME}
  PRIVATE
    $<IF:$<CXX_COMPILER_ID:MSVC>,
      /source-charset:utf-8 /Wall 
      /wd4061 /wd4244 /wd4251 /wd4365 /wd4464 /wd4514 /wd4571 /wd4574 /wd4623 /wd4625 /wd4626 /wd4668 /wd4710 /wd4711 /wd4774 /wd4820 /wd4946 /wd5026 /wd5027 /wd5039 /wd5045 /wd5052
      ${STACK_PROTECTOR_OPT},
      -Wall -Wextra
    >
    $<$<BOOL:$<CXX_COMPILER_ID:GNU>>:${STACK_PROTECTOR_OPT}>
)

if(ENABLE_SHARED OR USE_CFDCORE_SHARED)
target_compile_definitions(${PROJECT_NAME}
  PRIVATE
    CFD_CORE_SHARED=1
    ${ELEMENTS_COMP_OPT}
    ${CFD_ELEMENTS_USE}
)
else()
target_compile_definitions(${PROJECT_NAME}
  PRIVATE
    ${ELEMENTS_COMP_OPT}
    ${CFD_ELEMENTS_USE}
)
endif()

if((NOT wally_FOUND) OR (NOT ${wally_FOUND}))
target_include_directories(${PROJECT_NAME}
  PRIVATE
    .
    ../src
    ../src/include
)
target_link_directories(${PROJECT_NAME}
  PRIVATE
    ./
)
else()
target_include_directories(${PROJECT_NAME}
  PRIVATE
    .
    ../src
    ../src/include
    ${wally_DIR}/../include
)
target_link_directories(${PROJECT_NAME}
  PRIVATE
    ./
    ${wally_DIR}/../lib
)
endif()

target_link_libraries(${PROJECT_NAME}
  PRIVATE $<$<BOOL:$<CXX_COMPILER_ID:MSVC>>:winmm.lib>
  PRIVATE $<$<BOOL:$<CXX_COMPILER_ID:MSVC>>:ws2_32.lib>
  PRIVATE $<IF:$<OR:$<PLATFORM_ID:Darwin>,$<PLATFORM_ID:Windows>>,,rt>
  PRIVATE $<$<BOOL:$<CXX_COMPILER_ID:GNU>>:-static-libgcc>
  PRIVATE $<$<BOOL:$<CXX_COMPILER_ID:GNU>>:-static-libstdc++>
  PRIVATE $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:pthread>
  PRIVATE
    ${LIBWALLY_LIBRARY}
    ${UNIVALUE_LIBRARY}
    ${CFDCORE_LIBRARY}
    gtest_main
    gmock
)


add_test(
  NAME ${PROJECT_NAME}
  COMMAND $<TARGET_FILE:${PROJECT_NAME}>
  WORKING_DIRECTORY ${CFD_OBJ_BINARY_DIR}
)

endif()		# ENABLE_TESTS
