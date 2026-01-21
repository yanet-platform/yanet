dependencies = []
dependencies += libdpdk.get_variable('dpdk_dep')
dependencies += libjson.get_variable('nlohmann_json_dep')
dependencies += dependency('libsystemd')
dependencies += dependency('threads')
dependencies += dependency('gtest')
dependencies += dependency('gtest_main')

sources = files('unittest.cpp',
                'ip_address.cpp',
                'hashtable.cpp')

arch = 'corei7'
cpp_args_append = ['-march=' + arch, '-DCONFIG_YADECAP_UNITTEST']

unittest = executable('yanet-dataplane-unittest',
                      sources,
                      include_directories: yanet_rootdir,
                      dependencies: dependencies,
                      cpp_args: cpp_args_append,
                      override_options: 'b_lto=false')

test('dataplane',
     unittest,
     protocol: 'gtest')

unittest_neighbor = executable('yanet-dataplane-unittest-neighbor',
                               files('neighbor.cpp',
                                     '../neighbor.cpp',
                                     '../netlink.cpp',
                                     'unittest.cpp'),
                               include_directories: yanet_rootdir,
                               dependencies: dependencies + dependency('libnl-route-3.0'),
                               cpp_args: cpp_args_append + '-g',
                               override_options: 'b_lto=false')

test('neighbor', unittest_neighbor, protocol: 'gtest')
