project(
    'spdmapplib',
    'cpp',
    license: 'Apache-2.0',
    version: '1.0.0',
    default_options: [
        'warning_level=3',
        'werror=true',
        'cpp_std=c++20',
        'b_lundef=false',
    ],
)

yocto_build = get_option('yocto_dep')

dep_required = false

if yocto_build.enabled()
    dep_required = true
    message('yocto_build enabled')
else
    message('yocto_build disabled')
endif

libspdm = dependency('libspdm')
sdbusplus = dependency('sdbusplus')
sdbusplus_partial_dep = sdbusplus.partial_dependency(compile_args : false, link_args: true,
     includes : true, links: true)
boost = dependency('boost',
  modules: ['coroutine','context'],
  version: '>=1.75',
  fallback : ['boost', 'boost_dep'],
  static: false)
boost_dep = boost.partial_dependency(compile_args : false, link_args: true,
     includes : true, links: true)
mctpwplus = dependency('mctpwplus')

src_files = [
            'src/spdmapplib.cpp',
            'src/spdmapplib_requester_impl.cpp',
            'src/spdmapplib_responder_impl.cpp',
            'src/spdmtransport_mctp.cpp',
            'src/util.cpp',
            'src/library/spdm_transport_none_lib/common.cpp',
            'src/library/spdm_transport_none_lib/none.cpp'
            ]

deps = [
    libspdm,
    sdbusplus_partial_dep,
    mctpwplus
]

app_deps = [
    deps,
    boost_dep,
]

root_inc = include_directories(
                            'include',
                            'src/include')

mapfile = 'exportlist.txt'
spdmapplib = shared_library('spdmapplib',
                            src_files,
                            version: meson.project_version(),
                            install : true,
                            dependencies : deps,
                            include_directories: root_inc,
                            cpp_args : '-Wno-write-strings',
                            link_args: '-Wl,--version-script,@0@/@1@'.format(meson.current_source_dir(), mapfile))

install_headers(
            'include/spdmapplib.hpp',
            'include/spdmapplib_errorcodes.hpp',
            'include/spdmtransport.hpp',
            'include/spdmtransport_mctp.hpp'
            )

spdmapplib_dep = declare_dependency(include_directories : root_inc,
                                dependencies: app_deps,
                                link_with : spdmapplib)

subdir('sample_spdm_requester')

pkg = import('pkgconfig')
pkg.generate(
             spdmapplib,
             version : meson.project_version(),
             name : meson.project_name(),
             filebase : 'spdmapplib',
             requires : 'libsystemd',
             libraries : '-lsdbusplus -lboost_coroutine',
             description : 'Library for SPDM applications ',
)
