unittest_rteflow = executable('yanet-dataplane-unittest-rteflow',
                             ['../unittest.cpp', '../rteflow.cpp', '../../rteflow.cpp'],
                             include_directories: yanet_rootdir,
                             dependencies: dependencies,
                             cpp_args: cpp_args_append,
                             link_args: ['-Wl,--wrap=rte_flow_create',
                                         '-Wl,--wrap=rte_flow_destroy',
                                         '-Wl,--wrap=rte_malloc',
                                         '-Wl,--wrap=rte_free'],
                             override_options: 'b_lto=false')
test('rteflow', unittest_rteflow, timeout: 180, protocol: 'gtest')
