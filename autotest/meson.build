sources = files('autotest.cpp',
                'main.cpp',
                '../dataplane/dump_rings.cpp', # maybe it's better to just put implementation in the .h file
                '../dataplane/pcap_shm_device.cpp' # maybe it's better to just put implementation in the .h file
                )

#Create some shared thing?? or just everything in .h file..?

dependencies = []
dependencies += libdpdk.get_variable('dpdk_dep')
dependencies += libjson.get_variable('nlohmann_json_dep')
dependencies += dependency('libsystemd')
dependencies += dependency('yaml-cpp', static: true)
dependencies += dependency('libpcap', static: true)
dependencies += dependency('gmock')
dependencies += pcapplusplus_deps

executable('yanet-autotest',
           sources,
           include_directories: yanet_rootdir,
           dependencies: dependencies,
           link_args : ['-lstdc++fs'],
           override_options: 'b_lto=false',
           install: true)

install_data('yanet-autotest-run.py', install_dir: get_option('bindir'))
