dependencies = []
dependencies += dependency('threads')

sources = files('src/libyabird.cpp')

install_headers('src/libyabird.h')

libyabird = library('yanet-rib',
                    sources,
                    include_directories: yanet_rootdir,
                    dependencies: dependencies,
                    install: true)
