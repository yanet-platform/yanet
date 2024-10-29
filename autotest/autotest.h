#pragma once

#include <string>
#include <thread>
#include <vector>

#include <pcap.h>
#include <yaml-cpp/yaml.h>

#include "common/bufferring.h"
#include "common/icontrolplane.h"
#include "common/idataplane.h"
#include "common/result.h"
#include "common/sdpcommon.h"

namespace nAutotest
{

using ipv4_address_t = common::ipv4_address_t;
using ipv6_address_t = common::ipv6_address_t;
using ip_address_t = common::ip_address_t;
using ipv4_prefix_t = common::ipv4_prefix_t;
using ipv6_prefix_t = common::ipv6_prefix_t;
using ip_prefix_t = common::ip_prefix_t;
using community_t = common::community_t;
using large_community_t = common::large_community_t;

using namespace std::chrono_literals;
using Duration = std::chrono::system_clock::duration;
inline constexpr Duration DEFAULT_PACKET_READ_TIME_LIMIT = 2s;
inline constexpr Duration DEFAULT_STEP_TIME_LIMIT = 2s;
inline constexpr Duration READ_WAIT_UNTIL_RETRY = 1000us;
inline constexpr Duration WARN_WAIT_THRESHOLD = 10s;

class tAutotest
{
public:
	tAutotest();
	~tAutotest() = default;

	eResult init(const std::string& binaryPath,
	             bool dumpPackets,
	             const std::vector<std::string>& configFilePaths);

	void start();
	void join();

protected:
	void sendThread(std::string interfaceName, std::string sendFilePath);
	void recvThread(std::string interfaceName, std::vector<std::string> expectFilePaths, Duration timelimit);
	void dumpThread(std::string interfaceName, std::string dumpFilePath);

	bool step_ipv4Update(const YAML::Node& yamlStep);
	bool step_ipv4Remove(const YAML::Node& yamlStep);
	bool step_ipv4LabelledUpdate(const YAML::Node& yamlStep);
	bool step_ipv4LabelledRemove(const YAML::Node& yamlStep);
	bool step_ipv6Update(const YAML::Node& yamlStep);
	bool step_ipv6LabelledUpdate(const YAML::Node& yamlStep);
	bool step_sendPackets(const YAML::Node& yamlStep, const std::string& path);
	bool step_checkCounters(const YAML::Node& yamlStep);
	bool step_sleep(const YAML::Node& yamlStep);
	bool step_rib_insert(const YAML::Node& yamlStep);
	bool step_rib_remove(const YAML::Node& yamlStep);
	bool step_rib_clear(const YAML::Node& yamlStep);
	bool step_cli(const YAML::Node& yamlStep, const std::string& path);
	bool step_clearFWState();
	bool step_reload(const YAML::Node& yamlStep);
	bool step_values(const YAML::Node& yamlStep);
	bool step_cli_check(const YAML::Node& yamlStep);
	bool step_reload_async(const YAML::Node& yamlStep);
	bool step_echo(const YAML::Node& yamlStep);
	bool step_dumpPackets(const YAML::Node& yamlStep, const std::string& path);

	eResult initSockets();
	eResult initSharedMemory();
	void fflushSharedMemory();

	bool step_memorize_counter_value(const YAML::Node& yamlStep);
	bool step_diff_with_kept_counter_value(const YAML::Node& yamlStep);

protected:
	void mainThread();

	void convert_ipv4Update(const std::string& string);
	void convert_ipv4Remove(const std::string& string);
	void convert_ipv4LabelledUpdate(const std::string& string);
	void convert_ipv4LabelledRemove(const std::string& string);
	void convert_ipv6Update(const std::string& string);
	void convert_ipv6LabelledUpdate(const std::string& string);

	int cli(const std::string& command);

protected:
	bool dumpPackets;
	std::vector<std::string> configFilePaths;
	std::string configFilePath_current;

	interface::dataPlane dataPlane;
	interface::controlPlane controlPlane;
	common::sdp::DataPlaneInSharedMemory sdp_data;

	common::idp::getConfig::response dataPlaneConfig;
	common::idp::get_shm_info::response dataPlaneSharedMemory;

	std::map<std::string, ///< interfaceName
	         int>
	        pcaps;

	std::tuple<size_t, void*> rawShmInfo;
	std::map<std::string, common::PacketBufferRing> dumpRings;

	std::vector<std::thread> threads;
	volatile bool flagStop;

	std::map<ipv4_prefix_t,
	         std::set<std::string>>
	        pathInformations_ipv4Update;

	std::map<ipv4_prefix_t,
	         std::set<std::string>>
	        pathInformations_ipv4LabelledUpdate;

	std::map<ipv6_prefix_t,
	         std::set<std::string>>
	        pathInformations_ipv6Update; ///< @todo

	common::icp::loadConfig::request request;

	std::string memorized_counter_name;
	uint32_t memorized_coreId;
	uint64_t memorized_counter_value;
};

bool readTimeLimited(int fd, u_char* data, ssize_t len, std::chrono::system_clock::time_point time_to_give_up);

template<typename T>
bool readTimeLimited(int fd, T& data, std::chrono::system_clock::time_point time_to_give_up)
{
	return readTimeLimited(fd, reinterpret_cast<u_char*>(&data), sizeof(data), time_to_give_up);
}

}
