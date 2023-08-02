dependencies = []
dependencies += dependency('libsystemd')
dependencies += dependency('threads')
dependencies += dependency('gtest')
dependencies += dependency('gtest_main')
dependencies += libyanet_fwparser_dep

controlplane_sources = files('../src/acl_compiler.cpp',
                             '../src/acl.cpp',
                             '../src/acl_filter.cpp',
                             '../src/acl_network_table.cpp',
                             '../src/acl_total_table.cpp',
                             '../src/acl_transport.cpp',
                             '../src/acl_transport_table.cpp',
                             '../src/acl_value.cpp')

sources = files('unittest.cpp',
                'acl_flat.cpp',
                'acl.cpp',
                'acl_network.cpp',
                'acl_table.cpp',
                'acl_tree.cpp',
                'network.cpp',
                'parser.cpp',
                'type.cpp')

unittest = executable('yanet-controlplane-unittest',
                      [controlplane_sources, sources],
                      include_directories: yanet_rootdir,
                      dependencies: dependencies,
                      override_options: 'b_lto=false')

test('controlplane',
     unittest,
     protocol: 'gtest',
     timeout: 300)
