dependencies = []
dependencies += libyanet_fwparser_dep

sources = files('src/fw_dump.cpp',
                'src/main.cpp')

executable('yanet-parser',
           sources,
           include_directories: yanet_rootdir,
           dependencies: dependencies,
           install: true)
