dependencies = []
dependencies += dependency('libsystemd')
dependencies += dependency('threads')
dependencies += libyanet_fwparser_dep
dependencies += libyanet_protobuf_dep

sources = files('src/acl_compiler.cpp',
                'src/acl.cpp',
                'src/acl_filter.cpp',
                'src/acl_network_table.cpp',
                'src/acl_total_table.cpp',
                'src/acl_transport.cpp',
                'src/acl_transport_table.cpp',
                'src/acl_value.cpp',
                'src/balancer.cpp',
                'src/bus.cpp',
                'src/configconverter.cpp',
                'src/configparser.cpp',
                'src/controlplane.cpp',
                'src/dregress.cpp',
                'src/durations.cpp',
                'src/fqdn.cpp',
                'src/isystem.cpp',
                'src/main.cpp',
                'src/module.cpp',
                'src/nat64stateful.cpp',
                'src/protobus.cpp',
                'src/rib.cpp',
                'src/route.cpp',
                'src/telegraf.cpp',
                'src/tun64.cpp')

foreach arch : archs
    bin = 'yanet-controlplane'
    if archs.length() > 1
        bin += '-' + arch
    endif

    cpp_args_append = ['-march=' + arch]

    executable(bin,
               sources,
               include_directories: yanet_rootdir,
               dependencies: dependencies,
               cpp_args: cpp_args_append,
               install: true)
endforeach
