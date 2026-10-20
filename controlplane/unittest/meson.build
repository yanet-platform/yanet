dependencies = []
dependencies += libjson.get_variable('nlohmann_json_dep')
dependencies += dependency('libsystemd')
dependencies += dependency('threads')
dependencies += dependency('gtest')
dependencies += dependency('gtest_main')
dependencies += libyanet_fwparser_dep
if get_option('custom_hash_structures')
    dependencies += emhash_dep
    dependencies += ankerl_dep
endif

controlplane_sources = files('../configparser.cpp',
                             '../acl_compiler.cpp',
                             '../acl.cpp',
                             '../acl_filter.cpp',
                             '../acl_network_table.cpp',
                             '../acl_total_table.cpp',
                             '../acl_transport.cpp',
                             '../acl_transport_table.cpp',
                             '../acl_value.cpp')

sources = files('unittest.cpp',
                'acl_flat.cpp',
                'acl.cpp',
                'acl_network.cpp',
                'ndarray.cpp',
                'acl_tree.cpp',
                'network.cpp',
                'parser.cpp',
                'segment_allocator.cpp',
                'type.cpp',
                'isolation_config.cpp')

arch = 'corei7'
cpp_args_append = ['-march=' + arch]

unittest = executable('yanet-controlplane-unittest',
                      [controlplane_sources, sources],
                      include_directories: yanet_rootdir,
                      dependencies: dependencies,
                      cpp_args: cpp_args_append,
                      override_options: 'b_lto=false')

test('controlplane',
     unittest,
     protocol: 'gtest',
     timeout: 300)

memory_sources = files('../balancer.cpp',
                       '../bus.cpp',
                       '../configconverter.cpp',
                       '../controlplane.cpp',
                       '../dregress.cpp',
                       '../durations.cpp',
                       '../fqdn.cpp',
                       '../isystem.cpp',
                       '../memory_manager.cpp',
                       '../module.cpp',
                       '../nat46clat.cpp',
                       '../nat64stateful.cpp',
                       '../protobus.cpp',
                       '../rib.cpp',
                       '../route.cpp',
                       '../telegraf.cpp',
                       '../tun64.cpp',
                       'acl_history.cpp',
                       'acl_memory.cpp',
                       'balancer_retention.cpp',
                       'counter_memory.cpp',
                       'protobus.cpp',
                       'rib.cpp',
                       'rpc_channel.cpp',
                       'telegraf_retention.cpp')

# Separate from unittest: controlplane.cpp defines logPriority and acl_memory.cpp replaces operator new.
memory_unittest = executable('yanet-controlplane-memory-unittest',
                             [controlplane_sources, memory_sources],
                             include_directories: yanet_rootdir,
                             dependencies: dependencies + [libyanet_protobuf_dep],
                             cpp_args: cpp_args_append,
                             override_options: 'b_lto=false')

test('controlplane_memory',
     memory_unittest,
     protocol: 'gtest',
     timeout: 300)
