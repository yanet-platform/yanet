dependencies = []
dependencies += libjson.get_variable('nlohmann_json_dep')
dependencies += dependency('threads')
dependencies += libyanet_common_dep

sources = files('libyabird.cpp')

install_headers('libyabird.h')

libyabird = library('yanet-rib',
                    sources,
                    include_directories: yanet_rootdir,
                    dependencies: dependencies,
                    install: true)

libyabird_static = static_library('yanet-rib',
                                  sources,
                                  include_directories: yanet_rootdir,
                                  dependencies: dependencies,
                                  install: true)
