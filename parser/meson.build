dependencies = []
dependencies += libyanet_fwparser_dep

sources = files('fw_dump.cpp',
                'main.cpp')

executable('yanet-parser',
           sources,
           include_directories: yanet_rootdir,
           dependencies: dependencies,
           install: true)
