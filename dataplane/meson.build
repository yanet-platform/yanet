dataplane_common_sources = files(
    'dump_rings.cpp',
    'pcap_shm_device.cpp'
)

dataplane_common_dependencies = []
dataplane_common_dependencies += libdpdk.get_variable('dpdk_dep')
dataplane_common_dependencies += libjson.get_variable('nlohmann_json_dep')
dataplane_common_dependencies += pcapplusplus_deps

dataplane_common_lib = static_library('dataplane_common',
    dataplane_common_sources,
    include_directories: yanet_rootdir,
    dependencies: dataplane_common_dependencies
)

# Declare a dependency so it can be used in other subfolders
dataplane_common_dep = declare_dependency(
    link_with: dataplane_common_lib,
    include_directories: yanet_rootdir,
    dependencies: dataplane_common_dependencies
)

dependencies = []
dependencies += dependency('libsystemd')
dependencies += dependency('threads')
dependencies += [dataplane_common_dep]

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
