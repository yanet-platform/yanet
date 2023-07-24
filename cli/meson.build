dependencies = []
dependencies += libyanet_protobuf_dep

sources = files('src/config.cpp',
                'src/main.cpp')

executable('yanet-cli',
           sources,
           include_directories: yanet_rootdir,
           dependencies: dependencies,
           install: true)
