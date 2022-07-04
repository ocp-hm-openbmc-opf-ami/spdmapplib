cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

set(src_spdm_requester 
        ${PROJECT_SOURCE_DIR}/utility/spdm_requester.cpp)

ADD_EXECUTABLE(spdm_requester ${src_spdm_requester})

target_link_libraries(
    spdm_requester
    spdmapplib
    sdbusplus
    systemd
    boost_coroutine
    mctpwplus
    )

install(TARGETS spdm_requester DESTINATION bin)
