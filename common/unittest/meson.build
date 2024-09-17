dependencies = []
dependencies += libjson.get_variable('nlohmann_json_dep')
dependencies += dependency('threads')
dependencies += dependency('gtest')
dependencies += dependency('gtest_main')

common_sources = files()

sources = files('unittest.cpp',
                'static_vector.cpp',
                'shared_memory.cpp',
                'tuple.cpp',
                )

arch = 'corei7'
cpp_args_append = ['-march=' + arch]

unittest = executable('yanet-common-unittest',
                      [common_sources, sources],
                      include_directories: yanet_rootdir,
                      dependencies: dependencies,
                      cpp_args: cpp_args_append,
                      override_options: 'b_lto=false')

test('common',
     unittest,
     protocol: 'gtest')
