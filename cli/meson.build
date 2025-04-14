dependencies = []
dependencies += libdpdk.get_variable('dpdk_dep')
dependencies += libyanet_protobuf_dep
dependencies += libjson.get_variable('nlohmann_json_dep')
dependencies += dependency('threads')
dependencies += libyanet_common_dep

sources = files('config.cpp',
                'main.cpp')

executable('yanet-cli',
           sources,
           include_directories: yanet_rootdir,
           dependencies: dependencies,
           install: true)
