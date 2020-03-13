cmake_minimum_required(VERSION 3.13)

# configure.ac: AC_INIT([cfd-core], [1.0]
set(PACKAGE_VERSION   1.0.0)

####################
# options
####################
include(./cmake/CfdCommonOption.cmake)
include(./cmake/CfdWallyOption.cmake)


####################
# common setting
####################
include(./cmake/CfdCommonSetting.cmake)


####################
# test
####################
project(cfdcore_all_test CXX)
if(ENABLE_TESTS)
enable_testing()
endif()		# ENABLE_TESTS

####################
# subdirectories
####################
if(NOT CFD_SINGLE_BUILD)
add_subdirectory(external)
endif()
add_subdirectory(src/univalue)
add_subdirectory(src)


####################
# test subdirectories
####################
if(ENABLE_TESTS)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
include(CTest)
add_subdirectory(test)
endif()		# ENABLE_TESTS


####################
# install & export
####################
set(prefix            ${CMAKE_INSTALL_PREFIX})
set(exec_prefix       ${prefix})
set(libdir            ${exec_prefix}/lib)
set(includedir        ${prefix}/include)
include(GNUInstallDirs)

configure_file(pc/cfd-core.pc.in  cfd-core.pc  @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/cfd-core.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

####################
# uninstall
####################
if(NOT TARGET uninstall)
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/pc/cmake_uninstall.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
  IMMEDIATE @ONLY)

add_custom_target(uninstall
  COMMAND ${CMAKE_COMMAND} -P
  ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()
