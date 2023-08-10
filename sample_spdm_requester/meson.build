requester_src = [
    'spdm_requester.cpp',
    'util.cpp'
]

executable('spdm_requester',
    requester_src,
    dependencies: [ spdmapplib_dep ],
    install: true,
    install_dir:get_option('bindir'))

packagedir = join_paths(
    get_option('prefix'),
    get_option('datadir'),
    'spdmd',
)

certificates = [
    'bundle_requester.certchain.der',
    'end_requester.key'
]
filepaths = []
foreach c : certificates
    file = join_paths('sample_keys/rsa3072', c)
    install_data(
        file,
        install_dir: join_paths(
            packagedir,
            'sample_keys/rsa3072',
        )
    )
    filepaths += [file]
endforeach