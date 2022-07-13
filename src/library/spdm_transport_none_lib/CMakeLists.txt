cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

SET(src_spdm_transport_none_lib
    ${PROJECT_SOURCE_DIR}/src/library/spdm_transport_none_lib/common.cpp
    ${PROJECT_SOURCE_DIR}/src/library/spdm_transport_none_lib/none.cpp
)

ADD_LIBRARY(spdm_transport_none_lib STATIC ${src_spdm_transport_none_lib})
TARGET_LINK_LIBRARIES (
    spdm_transport_none_lib 
    spdm
)