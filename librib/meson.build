dependencies = []
dependencies += libjson.get_variable('nlohmann_json_dep')
dependencies += dependency('threads')

sources = files('libyabird.cpp')

install_headers('libyabird.h')

libyabird = both_libraries('yanet-rib',
                    sources,
                    include_directories: yanet_rootdir,
                    dependencies: dependencies,
                    install: true)
