dependencies = []
dependencies += libdpdk.get_variable('dpdk_dep')
dependencies += libjson.get_variable('nlohmann_json_dep')
dependencies += dependency('libsystemd')
dependencies += dependency('threads')
dependencies += pcapplusplus_deps

sources = files('bus.cpp',
                'controlplane.cpp',
                'dataplane.cpp',
                'debug_latch.cpp',
                'dpdk.cpp',
                'dregress.cpp',
                'fragmentation.cpp',
                'icmp_translations.cpp',
                'kernel_interface_handle.cpp',
                'kernel_interface_handler.cpp',
                'globalbase.cpp',
                'main.cpp',
                'memory_manager.cpp',
                'neighbor.cpp',
                'report.cpp',
                'dump_rings.cpp',
                'pcap_shm_device.cpp',
                'slow_worker.cpp',
                'sock_dev.cpp',
                'worker.cpp',
                'worker_gc.cpp',
                'icmp.cpp',
                'metadata.cpp')

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
                           '-DYANET_CONFIG_SUFFIX=' + yanet_config,
                           '-mlzcnt']

        executable(bin,
                   sources,
                   include_directories: yanet_rootdir,
                   dependencies: dependencies,
                   cpp_args: cpp_args_append,
                   override_options: ['cpp_eh=none', 'cpp_rtti=false'],
                   install: true)
    endforeach
endforeach
