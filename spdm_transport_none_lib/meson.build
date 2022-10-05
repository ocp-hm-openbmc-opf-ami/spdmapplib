cc=meson.get_compiler('c')
src_spdm_transport_none_lib = [
    'common.c',
    'none.c'
]
spdm_transport_none_lib = static_library('spdm_transport_none_lib',
                            src_spdm_transport_none_lib,
                            install : true,
                            dependencies : deps,
                            include_directories: root_inc,
                            link_language : 'c',
                            c_args : '-Wno-error=unused-parameter')

