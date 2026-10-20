#include <gtest/gtest.h>

#include <string>

#include <dirent.h>

#include "common/rpc_channel.h"

namespace
{

int open_descriptors()
{
	int count = 0;
	DIR* directory = opendir("/proc/self/fd");
	while (readdir(directory))
	{
		++count;
	}
	closedir(directory);
	return count;
}

TEST(RpcChannel, FailedConnectClosesSocket)
{
	const int before = open_descriptors();
	try
	{
		common::proto::UnixProtobufRpcChannel channel("/proc/self/fd/-1");
	}
	catch (const std::string&)
	{
	}
	EXPECT_EQ(open_descriptors(), before);
}

}
