dependencies = []
dependencies += libjson.get_variable('nlohmann_json_dep')

flex_token = custom_target('flex_token.l',
                           input: 'token.l',
                           output: ['@BASENAME@.cpp', '@BASENAME@.h'],
                           command: [find_program('flex'),
                                     '--outfile=@OUTPUT0@',
                                     '--header-file=@OUTPUT1@',
                                     '@INPUT@'])

bison_fw_parser = custom_target('bison_fw_parser.y',
                                depends: flex_token,
                                input: 'fw_parser.y',
                                output: ['@BASENAME@.cpp', '@BASENAME@.h', 'location.hh'],
                                command: [find_program('bison'),
                                          '-Wall',
                                          '--output=@OUTPUT0@',
                                          '--defines=@OUTPUT1@',
                                          '@INPUT@'])

sources = files('fw_config.cpp',
                'fw_lexer.cpp')

libyanet_fwparser = static_library('yanet-fwparser',
                                   [sources, flex_token, bison_fw_parser],
                                   dependencies: dependencies,
                                   include_directories: yanet_rootdir)

libyanet_fwparser_dep = declare_dependency(sources: [flex_token, bison_fw_parser],
                                           link_with: libyanet_fwparser)
