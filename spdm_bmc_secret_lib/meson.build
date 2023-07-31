cc=meson.get_compiler('c')
src_spdm_bmc_secret_lib = [
    'src/cert.c',
    'src/lib.c'
]

spdm_bmc_secret_lib = static_library('spdm_bmc_secret_lib',
                            src_spdm_bmc_secret_lib,
                            install : true,
                            dependencies : deps,
                            include_directories: root_inc, 
                            link_language : 'c',
                            c_args : ['-Wno-error=unused-parameter', '-Wno-error=pedantic','-Werror=sign-compare', '-Wno-sign-compare'])
