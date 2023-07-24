#pragma once

#include <string>


#ifndef YANET_VERSION_MAJOR
#define YANET_VERSION_MAJOR 0
#endif

#ifndef YANET_VERSION_MINOR
#define YANET_VERSION_MINOR 0
#endif

#ifndef YANET_VERSION_REVISION
#define YANET_VERSION_REVISION 00000000
#endif

#ifndef YANET_VERSION_HASH
#define YANET_VERSION_HASH 00000000
#endif

#ifndef YANET_VERSION_CUSTOM
#define YANET_VERSION_CUSTOM develop
#endif


namespace
{

#define YANET_HELPER_XSTRING(x) #x
#define YANET_HELPER_STRING(x) YANET_HELPER_XSTRING(x)

inline unsigned int version_major()
{
	return YANET_VERSION_MAJOR;
}

inline unsigned int version_minor()
{
	return YANET_VERSION_MINOR;
}

inline std::string version_revision()
{
	return YANET_HELPER_STRING(YANET_VERSION_REVISION);
}

inline std::string version_hash()
{
	return YANET_HELPER_STRING(YANET_VERSION_HASH);
}

inline std::string version_custom()
{
	return YANET_HELPER_STRING(YANET_VERSION_CUSTOM);
}

#undef YANET_HELPER_XSTRING
#undef YANET_HELPER_STRING

inline std::string version_to_string(const unsigned int major = YANET_VERSION_MAJOR,
                                     const unsigned int minor = YANET_VERSION_MINOR)
{
	std::string version(std::to_string(major) + "." + std::to_string(minor));
	return version;
}

inline std::string version_revision_to_string(const std::string revision = version_revision())
{
	return revision;
}

inline std::string version_hash_to_string(const std::string hash = version_hash())
{
	return hash;
}

inline std::string version_custom_to_string(const std::string custom = version_custom())
{
	return custom;
}

}
