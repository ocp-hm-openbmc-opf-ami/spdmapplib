cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

# Set project name here
PROJECT(spdmapplib VERSION 1.0.0 LANGUAGES CXX 
  DESCRIPTION "Library for SPDM applications.")
SET (BUILD_SHARED_LIBRARIES ON)
SET (CMAKE_CXX_STANDARD 17)

SET (CMAKE_CXX_STANDARD_REQUIRED ON)

SET(CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} \
    -Werror \
    -Wall \
    -Wextra \
    -Wshadow \
    -Wnon-virtual-dtor \
    -Wunused \
    -Woverloaded-virtual \
    -Wconversion \
    -Wnull-dereference \
    -Wdouble-promotion \
    -Wno-old-style-cast \
    -Wformat=2 \
    -Wno-write-strings  \
")
SET(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

# Add header and sources here
INCLUDE_DIRECTORIES(
    include 
    src/include 
    $ENV{PKG_CONFIG_SYSROOT_DIR}/usr/include/libspdm/include
    $ENV{PKG_CONFIG_SYSROOT_DIR}/usr/include/libspdm/include/hal/arm 
    $ENV{PKG_CONFIG_SYSROOT_DIR}/usr/include/libspdm/os_stub
    $ENV{PKG_CONFIG_SYSROOT_DIR}/usr/include/libspdm/os_stub/include
)

SET(src_spdmapplib
    ${PROJECT_SOURCE_DIR}/src/spdmapplib_requester_impl.cpp
    ${PROJECT_SOURCE_DIR}/src/spdmapplib_responder_impl.cpp
    ${PROJECT_SOURCE_DIR}/src/spdmtransport_mctp.cpp
    ${PROJECT_SOURCE_DIR}/src/util.cpp
    ${PROJECT_SOURCE_DIR}/src/library/spdm_transport_none_lib/common.cpp
    ${PROJECT_SOURCE_DIR}/src/library/spdm_transport_none_lib/none.cpp
    
)

SET(spdmapplib_headers
    ${PROJECT_SOURCE_DIR}/include/spdmapplib.hpp
    ${PROJECT_SOURCE_DIR}/include/spdmtransport.hpp
    ${PROJECT_SOURCE_DIR}/include/spdmtransport_mctp.hpp
    ${PROJECT_SOURCE_DIR}/include/spdmapplib_errorcodes.hpp
)

ADD_SUBDIRECTORY(utility/)

ADD_LIBRARY(${PROJECT_NAME} SHARED ${src_spdmapplib})
SET_TARGET_PROPERTIES(${PROJECT_NAME}  PROPERTIES VERSION 1.0.0 SOVERSION 1)
SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES LINK_FLAGS " -Wl,--version-script,${PROJECT_SOURCE_DIR}/exportlist.txt")

SET_TARGET_PROPERTIES(${PROJECT_NAME}
    PROPERTIES
    PUBLIC_HEADER "${spdmapplib_headers}"
)

TARGET_LINK_LIBRARIES (
    ${PROJECT_NAME} 
    spdm
)

INSTALL (TARGETS ${PROJECT_NAME} 
    LIBRARY DESTINATION lib
    PUBLIC_HEADER DESTINATION include
)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/lib/pkgconfig/spdmapplib.pc DESTINATION /usr/lib/pkgconfig)
SET(PKGCONF_REQ_PUB
    "libsystemd, mctpwplus"
)
CONFIGURE_FILE(spdmapplib.pc.in
  lib/pkgconfig/spdmapplib.pc @ONLY)

