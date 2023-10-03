dependencies = []
dependencies += dependency('protobuf', static: true)
dependencies += dependency('threads')

proto_sources = ['meta.proto',
                 'controlplane.proto']

targets = []
foreach proto_source : proto_sources
    targets += custom_target('protoc_' + proto_source,
                             input: proto_source,
                             output: ['@BASENAME@.pb.cc', '@BASENAME@.pb.h'],
                             command: [find_program('protoc'),
                                       '--proto_path=@CURRENT_SOURCE_DIR@',
                                       '--cpp_out=@OUTDIR@',
                                       '@INPUT@'])
endforeach

libyanet_protobuf = static_library('yanet-protobuf',
                                   targets,
                                   dependencies: dependencies)

libyanet_protobuf_dep = declare_dependency(sources: targets,
                                           link_with: libyanet_protobuf)
