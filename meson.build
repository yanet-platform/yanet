project('yanet', 'cpp',
        meson_version: '>= 0.61',
        default_options: ['cpp_std=c++20',
                          'buildtype=release',
                          'warning_level=2',
                          'werror=true',
                          'b_lto=true'])


yanet_rootdir = include_directories('.')

if get_option('buildtype').contains('release')
    add_global_arguments('-Ofast', language: 'cpp')
endif

add_global_arguments('-DYANET_VERSION_MAJOR=' + get_option('version_major').to_string(), language: 'cpp')
add_global_arguments('-DYANET_VERSION_MINOR=' + get_option('version_minor').to_string(), language: 'cpp')
add_global_arguments('-DYANET_VERSION_REVISION=' + get_option('version_revision'), language: 'cpp')
add_global_arguments('-DYANET_VERSION_HASH=' + get_option('version_hash'), language: 'cpp')
add_global_arguments('-DYANET_VERSION_CUSTOM=' + get_option('version_custom'), language: 'cpp')


if get_option('target').contains('buildenv')
    subdir('libprotobuf')
    subdir('libfwparser')
    subdir('parser')
    subdir_done()
elif get_option('target').contains('unittest')
    subdir('libfwparser')
    subdir('dataplane/unittest')
    subdir('controlplane/unittest')
    subdir_done()
endif


archs = ['corei7']
yanet_configs = ['release']

if get_option('target').contains('autotest')
    archs = ['corei7']
    yanet_configs = ['autotest']
endif

if get_option('arch').length() > 0
    archs = get_option('arch')
endif

if get_option('yanet_config').length() > 0
    yanet_configs = get_option('yanet_config')
endif


subdir('libprotobuf')
subdir('libfwparser')
subdir('dataplane')
subdir('controlplane')
subdir('cli')

if get_option('target').contains('release')
    subdir('logger')
    subdir('librib')

    install_data('yanet-init.sh',
                 rename: 'yanet-init',
                 install_dir: get_option('bindir'))

    install_data('yanet-announcer.py',
                 rename: 'yanet-announcer',
                 install_dir: get_option('bindir'))

    install_data('yanet-cli.bash_completion',
                 rename: 'yanet-cli',
                 install_dir: get_option('datadir') / 'bash-completion' / 'completions')

    install_data('yanet-cli.zsh_completion',
                 rename: '_yanet-cli',
                 install_dir: get_option('datadir') / 'zsh' / 'functions' / 'Completion' / 'Unix')
elif get_option('target').contains('autotest')
    subdir('autotest')
endif
