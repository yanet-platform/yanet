dependencies = []
dependencies += libjson.get_variable('nlohmann_json_dep')
dependencies += dependency('libsystemd')
dependencies += dependency('threads')
dependencies += libyanet_fwparser_dep
dependencies += libyanet_protobuf_dep
if get_option('custom_hash_structures')
    dependencies += emhash_dep
    dependencies += ankerl_dep
endif

sources = files('acl_compiler.cpp',
                'acl.cpp',
                'acl_filter.cpp',
                'acl_network_table.cpp',
                'acl_total_table.cpp',
                'acl_transport.cpp',
                'acl_transport_table.cpp',
                'acl_value.cpp',
                'balancer.cpp',
                'bus.cpp',
                'configconverter.cpp',
                'configparser.cpp',
                'controlplane.cpp',
                'dregress.cpp',
                'durations.cpp',
                'fqdn.cpp',
                'isystem.cpp',
                'main.cpp',
                'memory_manager.cpp',
                'module.cpp',
                'nat46clat.cpp',
                'nat64stateful.cpp',
                'protobus.cpp',
                'rib.cpp',
                'route.cpp',
                'telegraf.cpp',
                'tun64.cpp')

foreach arch : archs
    bin = 'yanet-controlplane'
    if archs.length() > 1
        bin += '-' + arch
    endif

    cpp_args_append = ['-march=' + arch]

    if yanet_configs.length() == 1
        cpp_args_append += '-DYANET_CONFIG_SUFFIX=' + yanet_config
    endif

    executable(bin,
               sources,
               include_directories: yanet_rootdir,
               dependencies: dependencies,
               cpp_args: cpp_args_append,
               install: true)
endforeach
