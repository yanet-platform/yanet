dependencies = []
dependencies += dependency('threads')

sources = files('libyabird.cpp')

install_headers('libyabird.h')

libyabird = library('yanet-rib',
                    sources,
                    include_directories: yanet_rootdir,
                    dependencies: dependencies,
                    install: true)
