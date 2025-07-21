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

executable('bench', [sources, dataplane_sources],
            include_directories: yanet_rootdir,
            dependencies: dependencies)