dependencies = []
dependencies += libdpdk.get_variable('dpdk_dep')
dependencies += libjson.get_variable('nlohmann_json_dep')
dependencies += dependency('libsystemd')
dependencies += dependency('threads')
dependencies += dependency('gtest')
dependencies += dependency('gtest_main')

dataplane_sources = files('../../dataplane/proxy.cpp',
                          '../../dataplane/local_pool.cpp',
                          '../../dataplane/syncookies.cpp',
                          '../../dataplane/globalbase.cpp',
                          '../../dataplane/memory_manager.cpp')

sources = files('rate_limit.cpp', 'conn_limit.cpp', 'limiters.cpp')

cpp_args_append = ['-DCONFIG_YADECAP_UNITTEST']

limiters = executable('limiters', [sources, dataplane_sources],
            include_directories: yanet_rootdir,
            dependencies: dependencies,
            cpp_args: cpp_args_append)

test('limiters',
     limiters,
     timeout: 180,
     protocol: 'gtest')