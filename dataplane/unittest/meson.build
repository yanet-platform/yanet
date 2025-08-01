dependencies = []
dependencies += libdpdk.get_variable('dpdk_dep')
dependencies += libjson.get_variable('nlohmann_json_dep')
dependencies += dependency('libsystemd')
dependencies += dependency('threads')
dependencies += dependency('gtest')
dependencies += dependency('gtest_main')

dataplane_sources = files('../local_pool.cpp',
                          '../globalbase.cpp',
                          '../syncookies.cpp',
                          '../memory_manager.cpp',
                          '../proxy.cpp')

sources = files('unittest.cpp',
                'ip_address.cpp',
                'hashtable.cpp',
                'sdp.cpp',
                'local_pool.cpp',
                'syncookies.cpp',
                'proxy_syn.cpp',
                'proxy.cpp')

arch = 'corei7'
cpp_args_append = ['-march=' + arch,
                   '-DCONFIG_YADECAP_UNITTEST']

unittest = executable('yanet-dataplane-unittest',
                      [dataplane_sources, sources],
                      include_directories: yanet_rootdir,
                      dependencies: dependencies,
                      cpp_args: cpp_args_append,
                      override_options: 'b_lto=false')

test('dataplane',
     unittest,
     timeout: 180,
     protocol: 'gtest')
