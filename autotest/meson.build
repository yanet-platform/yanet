sources = files('autotest.cpp',
                'main.cpp')

dependencies = []
dependencies += dependency('libsystemd')
dependencies += dependency('yaml-cpp', static: true)
dependencies += dependency('libpcap', static: true)
dependencies += dependency('gmock')

executable('yanet-autotest',
           sources,
           include_directories: yanet_rootdir,
           dependencies: dependencies,
           install: true)

install_data('yanet-autotest-run.py', install_dir: get_option('bindir'))
