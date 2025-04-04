dependencies = []
dependencies += dependency('libsystemd')
dependencies += dependency('yaml-cpp', static: true)
dependencies += dependency('gmock')
dependencies += [dataplane_common_dep]

sources = files('autotest.cpp',
                'main.cpp',
                )

executable('yanet-autotest',
           sources,
           include_directories: yanet_rootdir,
           dependencies: dependencies,
           link_args : ['-lstdc++fs'],
           override_options: 'b_lto=false',
           install: true)

install_data('yanet-autotest-run.py', install_dir: get_option('bindir'))
