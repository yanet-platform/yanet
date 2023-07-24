dependencies = []
dependencies += dependency('libsystemd')
dependencies += dependency('threads')
dependencies += dependency('gtest')
dependencies += dependency('gtest_main')

sources = files('acl_flat.cpp')

unittest = executable('yanet-controlplane-unittest',
                      sources,
                      include_directories: yanet_rootdir,
                      dependencies: dependencies,
                      override_options: 'b_lto=false')

test('controlplane',
     unittest,
     protocol: 'gtest')
