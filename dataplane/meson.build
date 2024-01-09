dependencies = []
dependencies += dependency('libdpdk', static: true)
dependencies += dependency('libsystemd')
dependencies += dependency('threads')

sources = files('bus.cpp',
                'controlplane.cpp',
                'dataplane.cpp',
                'debug_latch.cpp',
                'dregress.cpp',
                'fragmentation.cpp',
                'globalbase.cpp',
                'main.cpp',
                'neighbor.cpp',
                'report.cpp',
                'sharedmemory.cpp',
                'sock_dev.cpp',
                'worker.cpp',
                'worker_gc.cpp')

foreach arch : archs
    foreach yanet_config : yanet_configs
        bin = 'yanet-dataplane'
        if archs.length() > 1
            bin += '-' + arch
        endif
        if yanet_configs.length() > 1
            bin += '-' + yanet_config
        endif

        cpp_args_append = ['-march=' + arch,
                           '-DYANET_CONFIG_SUFFIX=' + yanet_config]

        executable(bin,
                   sources,
                   include_directories: yanet_rootdir,
                   dependencies: dependencies,
                   cpp_args: cpp_args_append,
                   override_options: ['cpp_eh=none', 'cpp_rtti=false'],
                   install: true)
    endforeach
endforeach
