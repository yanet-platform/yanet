dependencies = []
dependencies += libjson.get_variable('nlohmann_json_dep')
dependencies += dependency('libsystemd')
dependencies += dependency('threads')
dependencies += dependency('gtest')
dependencies += dependency('gtest_main')
dependencies += libyanet_fwparser_dep

controlplane_sources = files('../acl_compiler.cpp',
                             '../acl.cpp',
                             '../acl_filter.cpp',
                             '../acl_network_table.cpp',
                             '../acl_total_table.cpp',
                             '../acl_transport.cpp',
                             '../acl_transport_table.cpp',
                             '../acl_value.cpp')

sources = files('unittest.cpp',
                'acl_flat.cpp',
                'acl.cpp',
                'acl_network.cpp',
                'ndarray.cpp',
                'acl_tree.cpp',
                'network.cpp',
                'parser.cpp',
                'type.cpp')

arch = 'corei7'
cpp_args_append = ['-march=' + arch]

unittest = executable('yanet-controlplane-unittest',
                      [controlplane_sources, sources],
                      include_directories: yanet_rootdir,
                      dependencies: dependencies,
                      cpp_args: cpp_args_append,
                      override_options: 'b_lto=false')

test('controlplane',
     unittest,
     protocol: 'gtest',
     timeout: 300)
