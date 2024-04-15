dependencies = []
dependencies += libdpdk.get_variable('dpdk_dep')
dependencies += libyanet_protobuf_dep
dependencies += dependency('threads')

sources = files('config.cpp',
                'main.cpp')

executable('yanet-cli',
           sources,
           include_directories: yanet_rootdir,
           dependencies: dependencies,
           install: true)
