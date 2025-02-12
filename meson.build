project('yanet', 'cpp',
        meson_version: '>= 0.61',
        default_options: ['cpp_std=c++17',
                          'buildtype=release',
                          'warning_level=2',
                          'werror=true',
                          'b_lto=true'])

yanet_rootdir = include_directories('.')

target_option = get_option('target')
arch_option = get_option('arch')
yanet_config_option = get_option('yanet_config')
bindir_option = get_option('bindir')
datadir_option = get_option('datadir')

compiler_args = []

if get_option('buildtype').contains('release')
    compiler_args += '-Ofast'
endif

compiler_args += [
    '-DYANET_VERSION_MAJOR=' + get_option('version_major').to_string(),
    '-DYANET_VERSION_MINOR=' + get_option('version_minor').to_string(),
    '-DYANET_VERSION_REVISION=' + get_option('version_revision'),
    '-DYANET_VERSION_HASH=' + get_option('version_hash'),
    '-DYANET_VERSION_CUSTOM=' + get_option('version_custom'),
]

if get_option('enable_acl_debug')
    compiler_args += '-DACL_DEBUG'
endif

if get_option('custom_hash_structures')
    # This is header-only library without meson.build
    emhash_dep = declare_dependency(include_directories: 'subprojects/emhash')
    add_global_arguments('-DCUSTOM_HASH_STRUCTURES', language: 'cpp')
endif

# Add all global arguments at once
add_global_arguments(compiler_args, language: 'cpp')

add_global_arguments('-DGOOGLE_PROTOBUF_NO_RTTI', language: 'cpp')

add_project_link_arguments('-lnuma', language : 'cpp')

add_global_arguments('-Wno-unused-parameter', language: 'cpp')

if target_option.contains('librib')
    libjson = subproject('json')
    subdir('librib')
    subdir_done()
endif

libdpdk = subproject('dpdk', default_options: [
    'platform=generic',
    'cpu_instruction_set=corei7',
    'pkt_mbuf_headroom=256',
    'disable_apps=dumpcap,graph,pdump,proc-info,test-acl,test-bbdev,test-cmdline,test-compress-perf,test-crypto-perf,test-dma-perf,test-eventdev,test-fib,test-flow-perf,test-gpudev,test-mldev,test-pipeline,test-pmd,test-regex,test-sad,test-security-perf',
    'disable_libs=bitratestats,cfgfile,flow_classify,gpudev,gro,gso,kni,jobstats,latencystats,metrics,node,pdump,pipeline,port,power,table,vhost',
    'enable_driver_sdk=true', 'disable_drivers=net/mlx4',
    'default_library=static', 'tests=false' ] )

libjson = subproject('json')

if target_option.contains('buildenv')
    subdir('libprotobuf')
    subdir('libfwparser')
    subdir('parser')
    subdir_done()
elif target_option.contains('unittest')
    subdir('libprotobuf')
    subdir('libfwparser')
    subdir('dataplane/unittest')
    subdir('controlplane/unittest')
    subdir('cli/unittest')
    subdir('common/unittest')
    subdir_done()
endif

archs = ['corei7']
yanet_configs = ['release']

if target_option.contains('autotest')
    archs = ['corei7']
    yanet_configs = ['autotest']
endif

if arch_option.length() > 0
    archs = arch_option
endif

if yanet_config_option.length() > 0
    yanet_configs = yanet_config_option
endif

subdir('libprotobuf')
subdir('libfwparser')
subdir('dataplane')
subdir('controlplane')
subdir('cli')

if target_option.contains('release')
    subdir('logger')
    subdir('librib')

    install_data('yanet-init.sh',
                 rename: 'yanet-init',
                 install_dir: bindir_option)

    install_data('yanet-announcer.py',
                 rename: 'yanet-announcer',
                 install_dir: bindir_option)

    install_data('yanet-cli.bash_completion',
                 rename: 'yanet-cli',
                 install_dir: datadir_option / 'bash-completion' / 'completions')

    install_data('yanet-cli.zsh_completion',
                 rename: '_yanet-cli',
                 install_dir: datadir_option / 'zsh' / 'functions' / 'Completion' / 'Unix')

    install_data('yanet-wrapper', install_dir: bindir_option)

    install_data('yanet-rebind.sh',
                 rename: 'yanet-rebind',
                 install_dir: bindir_option)
elif target_option.contains('autotest')
    subdir('autotest')
endif
