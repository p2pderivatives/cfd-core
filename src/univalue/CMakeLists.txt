cmake_minimum_required(VERSION 3.13)

# configure.ac: AC_INIT([univalue], [1.0.4]
set(VERSION   1.0.4)

cmake_policy(SET CMP0076 NEW)

####################
# options
####################
include(../../cmake/EnableCcache.cmake)
include(../../cmake/CfdCommonSetting.cmake)
include(../../cmake/CfdCommonOption.cmake)


####################
# univalue
####################
project(univalue CXX)
include(../../cmake/Cpp11Setting.cmake)

if(ENABLE_SHARED)
add_library(${PROJECT_NAME} SHARED)
else()
add_library(${PROJECT_NAME} STATIC)
endif()
target_sources(${PROJECT_NAME}
  PRIVATE
    lib/univalue.cpp
    lib/univalue_get.cpp
    lib/univalue_read.cpp
    lib/univalue_write.cpp
    include/univalue.h
    lib/univalue_escapes.h
    lib/univalue_utffilter.h
)

target_compile_options(${PROJECT_NAME}
  PRIVATE
    $<IF:$<CXX_COMPILER_ID:MSVC>,
      /LD /source-charset:utf-8 /wd4251 ${STACK_PROTECTOR_OPT},
      -Wall -Wextra -Wno-unused-function
    >
    $<$<BOOL:$<CXX_COMPILER_ID:GNU>>:${STACK_PROTECTOR_OPT}>
)
target_compile_definitions(${PROJECT_NAME}
  PRIVATE
    UNIVALUE_BUILD=1
)
target_include_directories(${PROJECT_NAME}
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    lib
)

target_link_libraries(${PROJECT_NAME}
  PRIVATE $<$<BOOL:$<CXX_COMPILER_ID:GNU>>:-static-libgcc>
  PRIVATE $<$<BOOL:$<CXX_COMPILER_ID:GNU>>:-static-libstdc++>
)

####################
# install & export
####################
set(prefix            ${CMAKE_INSTALL_PREFIX})
set(exec_prefix       ${prefix})
set(libdir            ${exec_prefix}/lib)
set(includedir        ${prefix}/include)
include(GNUInstallDirs)
set(CMAKE_INCLUDE_CURRENT_DIR_IN_INTERFACE ON) 

configure_file(pc/libunivalue.pc.in  libunivalue.pc  @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libunivalue.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
configure_file(pc/libunivalue.pc.in  univalue.pc  @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/univalue.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

configure_file(pc/libunivalue-uninstalled.pc.in  libunivalue-uninstalled.pc  @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libunivalue-uninstalled.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
configure_file(pc/libunivalue-uninstalled.pc.in  univalue-uninstalled.pc  @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/univalue-uninstalled.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

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

#export(TARGETS ${PROJECT_NAME}
#       APPEND FILE ${PROJECT_BINARY_DIR}/${PROJECT_NAME}-export.cmake
#       EXPORT_LINK_INTERFACE_LIBRARIES)

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/"
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING PATTERN "*.h")

if(MSVC)
install(DIRECTORY "${CFD_OBJ_BINARY_DIR}/"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        FILES_MATCHING PATTERN "univalue.exp")
endif()
