dependencies = []
dependencies += dependency('libdpdk', static: true)
dependencies += dependency('libsystemd')
dependencies += dependency('threads')
dependencies += dependency('gtest')
dependencies += dependency('gtest_main')

sources = files('unittest.cpp',
                'ip_address.cpp',
                'lpm.cpp',
                'hashtable.cpp')

unittest = executable('yanet-dataplane-unittest',
                      sources,
                      include_directories: yanet_rootdir,
                      dependencies: dependencies,
                      override_options: 'b_lto=false')

test('dataplane',
     unittest,
     protocol: 'gtest')
