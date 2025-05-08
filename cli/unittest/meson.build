dependencies = []
dependencies += libyanet_protobuf_dep
dependencies += libjson.get_variable('nlohmann_json_dep')
dependencies += dependency('threads')
dependencies += dependency('gtest')
dependencies += dependency('gtest_main')
dependencies += libyanet_common_dep

cli_sources = files()

sources = files('unittest.cpp',
                'call.cpp',
                )

unittest = executable('yanet-cli-unittest',
                      [cli_sources, sources],
                      include_directories: yanet_rootdir,
                      dependencies: dependencies,
                      cpp_args: cpp_args_append,
                      override_options: 'b_lto=false')

test('cli',
     unittest,
     protocol: 'gtest',
     timeout: 300)
