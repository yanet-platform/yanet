dependencies = []
dependencies += libdpdk.get_variable('dpdk_dep')
dependencies += dependency('libsystemd')
dependencies += dependency('threads')

sources = files('main.cpp')

cpp_args = []
cpp_args += '-fno-rtti'
cpp_args += '-march=corei7'

executable('yanet-logger',
           sources,
           include_directories: yanet_rootdir,
           dependencies: dependencies,
           cpp_args: cpp_args,
           install: true)
