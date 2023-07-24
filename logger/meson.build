dependencies = []
dependencies += dependency('libdpdk', static: true)
dependencies += dependency('libsystemd')
dependencies += dependency('threads')

sources = files('src/main.cpp')

cpp_args = []
cpp_args += '-fno-rtti'

executable('yanet-logger',
           sources,
           include_directories: yanet_rootdir,
           dependencies: dependencies,
           cpp_args: cpp_args,
           install: true)
