dependencies = []
dependencies += libdpdk.get_variable('dpdk_dep')
dependencies += libjson.get_variable('nlohmann_json_dep')
dependencies += dependency('libsystemd')
dependencies += dependency('threads')
dependencies += dependency('gtest')
dependencies += dependency('gtest_main')

sources = files('unittest.cpp',
                'ip_address.cpp',
                'hashtable.cpp',
                'isolation_request.cpp')

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

unittest_isolation = executable('yanet-dataplane-unittest-isolation',
                               ['isolation.cpp',
                                'isolation_worker.cpp',
                                '../dataplane.cpp',
                                '../rteflow.cpp',
                                '../report.cpp',
                                '../controlplane.cpp',
                                '../globalbase.cpp',
                                '../dregress.cpp',
                                '../fragmentation.cpp',
                                '../bus.cpp',
                                '../memory_manager.cpp',
                                '../neighbor.cpp',
                                '../netlink.cpp'],
                               include_directories: yanet_rootdir,
                               dependencies: dependencies + dependency('libnl-route-3.0'),
                               cpp_args: cpp_args_append + ['-mlzcnt', '-ffunction-sections', '-fdata-sections'],
                               link_args: ['-Wl,--gc-sections',
                                           '-Wl,--wrap=numa_node_of_cpu',
                                           '-Wl,--wrap=rte_flow_create',
                                           '-Wl,--wrap=rte_flow_destroy',
                                           '-Wl,--wrap=rte_malloc',
                                           '-Wl,--wrap=rte_free'],
                               override_options: 'b_lto=false')
test('controlplane-isolation', unittest_isolation, timeout: 180, protocol: 'gtest')
