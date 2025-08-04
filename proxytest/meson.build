dependencies = []
dependencies += libdpdk.get_variable('dpdk_dep')
dependencies += libjson.get_variable('nlohmann_json_dep')
dependencies += dependency('libsystemd')
dependencies += dependency('threads')

dataplane_sources = files('../dataplane/proxy.cpp',
                          '../dataplane/local_pool.cpp',
                          '../dataplane/syncookies.cpp',
                          '../dataplane/globalbase.cpp',
                          '../dataplane/memory_manager.cpp')

sources = files('main.cpp', 'proxytest.cpp', 'benchmark.cpp')

cpp_args_append = ['-DCONFIG_YADECAP_UNITTEST']

executable('bench', [sources, dataplane_sources],
            include_directories: yanet_rootdir,
            dependencies: dependencies,
            cpp_args: cpp_args_append)