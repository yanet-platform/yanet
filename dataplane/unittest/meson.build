dependencies = []
dependencies += libdpdk.get_variable('dpdk_dep')
dependencies += dependency('libsystemd')
dependencies += dependency('threads')
dependencies += dependency('gtest')
dependencies += dependency('gtest_main')

sources = files('unittest.cpp',
                'ip_address.cpp',
                'hashtable.cpp')

arch = 'corei7'
cpp_args_append = ['-march=' + arch]

unittest = executable('yanet-dataplane-unittest',
                      sources,
                      include_directories: yanet_rootdir,
                      dependencies: dependencies,
                      cpp_args: cpp_args_append,
                      override_options: 'b_lto=false')

test('dataplane',
     unittest,
     protocol: 'gtest')
