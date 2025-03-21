#include <arpa/inet.h>
#include <cstring>
#include <pcap.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#include <experimental/filesystem>
#include <fstream>
#include <thread>
#include <utility>

#include <gmock/gmock.h>

#include "autotest.h"
#include "common.h"

#include "common/define.h"
#include "common/result.h"
#include "common/sdpclient.h"
#include "common/sdpcommon.h"
#include "common/utils.h"
#include "dataplane/dump_rings.h"

#define MAX_PACK_LEN 16384
#define SOCK_DEV_PREFIX "sock_dev:"

namespace
{

template<std::size_t N>
constexpr std::size_t str_length(char const (&)[N])
{
	return N - 1;
}

} // namespace

struct __attribute__((__packed__)) packHeader
{
	uint32_t data_length;
};

namespace nAutotest
{

static const std::tuple<ip_address_t,
                        std::string,
                        uint32_t,
                        std::vector<uint32_t>,
                        std::set<community_t>,
                        std::set<large_community_t>,
                        uint32_t>
        attribute_default = {{}, "incomplete", 0, {}, {}, {}, 0};

tAutotest::tAutotest() :
        dumpPackets(true), flagStop(false)
{
	::testing::GTEST_FLAG(throw_on_failure) = true;
}

eResult tAutotest::init(const std::string& binaryPath,
                        bool dumpPackets,
                        const std::vector<std::string>& configFilePaths)
{
	GCC_BUG_UNUSED(binaryPath);
	this->dumpPackets = dumpPackets;
	this->configFilePaths = configFilePaths;

	if (auto ret = initSockets(); ret != eResult::success)
	{
		return ret;
	}

	if (auto ret = initSharedMemory(); ret != eResult::success)
	{
		return ret;
	}

	if (auto ret = common::sdp::SdpClient::ReadSharedMemoryData(sdp_data, true); ret != eResult::success)
	{
		return ret;
	}

	return eResult::success;
}

eResult tAutotest::initSockets()
{
	dataPlaneConfig = dataPlane.getConfig();

	for (const auto& port : std::get<0>(dataPlaneConfig))
	{
		const auto& interfaceName = std::get<0>(port.second);
		const auto& pci = std::get<3>(port.second);

		if (strncmp(pci.data(), SOCK_DEV_PREFIX, strlen(SOCK_DEV_PREFIX)) != 0)
		{
			YANET_LOG_ERROR("error: only sockdev is supported");
			return eResult::errorSocket;
		}

		int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
		if (fd < 0)
		{
			YANET_LOG_ERROR("error: could not create socket: %s\n", strerror(errno));
			return eResult::errorSocket;
		}
		struct sockaddr_un sockaddr;
		sockaddr.sun_family = AF_UNIX;
		strncpy(sockaddr.sun_path, pci.data() + strlen(SOCK_DEV_PREFIX), sizeof(sockaddr.sun_path) - 1);
		if (connect(fd, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) < 0)
		{
			YANET_LOG_ERROR("error: could not connect: %s\n", strerror(errno));
			return eResult::errorSocket;
		}
		pcaps[interfaceName] = fd;
	}

	return eResult::success;
}

eResult tAutotest::FillShmKeyMemoryMap(std::unordered_map<key_t, void*>& map)
{
	key_t ipc_key = 0;
	int shm_id = 0;
	void* shm_addr = nullptr;

	for (const auto& shm_info : dataPlaneSharedMemory)
	{
		ipc_key = std::get<5>(shm_info);

		if (map.find(ipc_key) != map.end())
		{
			// we already assigned an address for this key
			continue;
		}

		shm_id = shmget(ipc_key, 0, 0);
		if (shm_id == -1)
		{
			YANET_LOG_ERROR("shmget(%d, 0, 0) = %d\n", ipc_key, errno);
			return eResult::errorInitSharedMemory;
		}

		shm_addr = shmat(shm_id, nullptr, 0);
		if (shm_addr == (void*)-1)
		{
			YANET_LOG_ERROR("shmat(%d, nullptr, 0) = %d\n", shm_id, errno);
			return eResult::errorInitSharedMemory;
		}

		map[ipc_key] = shm_addr;
	}

	// rawShmInfo is needed to flush shared memory,
	// which is necessary to reset state in between tests
	if (!map.empty())
	{
		struct shmid_ds shm_info;
		if (shmctl(shm_id, IPC_STAT, &shm_info) == -1)
		{
			YANET_LOG_ERROR("shmctl(%d, IPC_STAT, &shm_info) = %d\n", shm_id, errno);
			return eResult::errorInitSharedMemory;
		}

		rawShmInfo = {shm_info.shm_segsz, shm_addr};
	}

	return eResult::success;
}

eResult tAutotest::initSharedMemory()
{
	dataPlaneSharedMemory = dataPlane.get_shm_info();

	std::unordered_map<key_t, void*> shm_by_key;

	if (eResult res = FillShmKeyMemoryMap(shm_by_key); res != eResult::success)
	{
		return res;
	}

	for (const auto& [ring_name, dump_tag, dump_config, core_id, socket_id, ipc_key, offset] : dataPlaneSharedMemory)
	{
		GCC_BUG_UNUSED(dump_tag);
		GCC_BUG_UNUSED(core_id);
		GCC_BUG_UNUSED(socket_id);

		auto memaddr = utils::ShiftBuffer(shm_by_key[ipc_key], offset);

		dumpRings[ring_name] = dumprings::CreateSharedMemoryDumpRing(dump_config, memaddr);
	}

	return eResult::success;
}

void tAutotest::start()
{
	threads.emplace_back([this] { mainThread(); });
}

void tAutotest::join()
{
	for (auto& thread : threads)
	{
		if (thread.joinable())
		{
			thread.join();
		}
	}
}

static int
writeIovCount(int fd, struct iovec* iov, size_t count)
{
	while (count > 0)
	{
		ssize_t written = writev(fd, iov, count);
		if (written < 0)
		{
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				return -1;
			continue;
		}
		/// Adjust iov
		while (written > 0)
		{
			if (iov->iov_len <= (size_t)written) /// Vec was consumed
			{
				written -= iov->iov_len;
				++iov;
				--count;
				continue;
			}
			iov->iov_base = (void*)((intptr_t)iov->iov_base + written);
			iov->iov_len -= written;
			written = 0;
		}
	}
	return 1;
}

void tAutotest::sendThread(std::string interfaceName,
                           std::string sendFilePath)
{
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_offline(sendFilePath.data(),
	                                 pcap_errbuf);
	if (!pcap)
	{
		YANET_LOG_ERROR("error: pcap_open_offline(): %s\n", pcap_errbuf);
		throw "";
	}

	pcap_pkthdr* header = nullptr;
	const u_char* data = nullptr;
	static u_char zeros[MAX_PACK_LEN];

	auto iface = pcaps[interfaceName];

	uint64_t packetsCount = 0;
	while (pcap_next_ex(pcap, &header, &data) >= 0)
	{

		struct packHeader hdr;
		hdr.data_length = htonl(header->len);

		struct iovec iov[3];
		size_t iov_count = 2;

		iov[0].iov_base = &hdr;
		iov[0].iov_len = sizeof(hdr);

		iov[1].iov_base = (void*)data;
		iov[1].iov_len = header->caplen;

		if (header->caplen < header->len)
		{
			iov[2].iov_base = (void*)zeros;
			iov[2].iov_len = header->len - header->caplen;
			iov_count = 3;
		}

		if (writeIovCount(iface, iov, iov_count) < 0)
		{
			YANET_LOG_ERROR("error: write packet(): %s\n", strerror(errno));
			throw "";
		}

		packetsCount++;
	}

	YANET_LOG_DEBUG("send %lu packets\n", packetsCount);

	pcap_close(pcap);
}

bool readTimeLimited(int fd, u_char* buf, ssize_t len, std::chrono::system_clock::time_point time_to_give_up)
{
	ssize_t ret = 0;
	while (len > 0 && std::chrono::system_clock::now() < time_to_give_up)
	{
		ret = read(fd, buf, len);
		switch (ret)
		{
			case 0:
				YANET_LOG_ERROR("Failed to read packets: end of file\n");
				return false;
			case -1:
				if ((errno == EAGAIN) || (errno = EWOULDBLOCK))
				{
					std::this_thread::sleep_for(READ_WAIT_UNTIL_RETRY);
				}
				else
				{
					YANET_LOG_ERROR("Failed to read packets: %s\n", strerror(errno));
					return false;
				}
				break;
			default:
				len -= ret;
				buf += ret;
				break;
		}
	}

	return len == 0;
}

static bool readPacket(int fd, pcap_pkthdr* header, u_char* data, Duration timelimit)
{
	auto time_to_give_up = std::chrono::system_clock::now() + timelimit;

	struct packHeader hdr;
	if (!readTimeLimited(fd, hdr, time_to_give_up))
	{
		return false;
	}

	hdr.data_length = ntohl(hdr.data_length);

	if (hdr.data_length == 0)
	{
		YANET_LOG_ERROR("error: read size is 0\n");
		throw "";
	}

	if (!readTimeLimited(fd, data, hdr.data_length, time_to_give_up))
	{
		return false;
	}

	header->len = hdr.data_length;
	header->caplen = header->len;
	return true;
}

template<typename IT = const u_char*, unsigned lcount = 16>
class TextDumper
{
public:
	TextDumper()
	{
		for (size_t i = 0; i < lcount; i++)
		{
			memcpy(buf + i * symSize, symPlacholder, symSize);
			memcpy(buf + lcount * symSize + sepSize + i * symSize, symPlacholder, symSize);
		}
		memcpy(buf + lcount * symSize, separator, sepSize);
		buf[bufSize - 1] = 0;
	}

	void dump(IT b1, IT e1, IT b2, IT e2)
	{
		for (unsigned line = 0; b1 != e1 || b2 != e2; line++)
		{
			for (size_t i = 0; i < lcount; i++)
			{
				bool dif = isDiffer(b1, e1, b2, e2);
				hex(i * symSize, b1, e1, dif);
				hex(lcount * symSize + sepSize + i * symSize, b2, e2, dif);
			}
			YANET_LOG_DEBUG("%04u:%s" ANSI_COLOR_RESET "\n", line * lcount, buf);
		}
	}

private:
	static bool isDiffer(IT b1, IT e1, IT b2, IT e2)
	{
		if (b1 == e1 && b2 != e2)
			return true;
		if (b1 != e1 && b2 == e2)
			return true;
		if (b1 == e1 && b2 == e2)
			return false;
		return *b1 != *b2;
	}

	void hex(size_t offset, IT& b, IT e, bool dif)
	{
		buf[offset + 4] = dif ? '1' : '2';
		if (b != e)
		{
			buf[offset + 6] = hexStr[(*b & 0xf0) >> 4];
			buf[offset + 7] = hexStr[*b & 0xf];
			b++;
		}
		else
		{
			buf[offset + 6] = ' ';
			buf[offset + 7] = ' ';
		}
	}

	constexpr static char symPlacholder[] = " \x1b[32mxx";
	constexpr static size_t symSize = str_length(symPlacholder);
	constexpr static char separator[] = ANSI_COLOR_RESET " |";
	constexpr static size_t sepSize = str_length(separator);
	constexpr static size_t bufSize = sepSize + symSize * lcount * 2;
	char buf[bufSize];

	constexpr static const char hexStr[] = "0123456789abcdef";
};

class PcapDumper
{
public:
	PcapDumper(std::string path, int capsize = MAX_PACK_LEN) :
	        tmpFilePath(std::move(path)), pcap(pcap_open_dead(DLT_EN10MB, capsize))
	{

		if (!pcap)
		{
			YANET_LOG_ERROR("error: pcap_open_dead()\n");
			throw "";
		}

		dumper = pcap_dump_open(pcap, tmpFilePath.data());
		if (!dumper)
		{
			pcap_close(pcap);
			YANET_LOG_ERROR("error: pcap_dump_open()\n");
			throw "";
		}
	}

	~PcapDumper()
	{
		pcap_close(pcap);
		pcap_dump_close(dumper);
	}

	void dump(pcap_pkthdr* header, const u_char* data)
	{
		pcap_dump((u_char*)dumper, header, data);
	}

	[[nodiscard]] std::string path() const
	{
		return tmpFilePath;
	}

private:
	const std::string tmpFilePath;
	pcap_t* pcap;
	pcap_dumper_t* dumper;
};

void tAutotest::dumpThread(std::string interfaceName,
                           std::string dumpFilePath)
{
	PcapDumper pcapDumper(dumpFilePath);
	u_char buffer[MAX_PACK_LEN];
	pcap_pkthdr tmp_pcap_packetHeader;
	auto iface = pcaps[interfaceName];
	uint64_t packetsCount = 0;

	for (;;)
	{
		if (!readPacket(iface, &tmp_pcap_packetHeader, buffer, DEFAULT_PACKET_READ_TIME_LIMIT))
		{
			break;
		}

		pcapDumper.dump(&tmp_pcap_packetHeader, buffer);
		packetsCount++;
	}

	YANET_LOG_DEBUG("received and dumped %lu packets\n", packetsCount);
}

class pcap_expectation
{
public:
	pcap_expectation(std::string filename) :
	        filename(filename), buffer(MAX_PACK_LEN, 0)
	{
		char pcap_errbuf[PCAP_ERRBUF_SIZE];
		pcap = pcap_open_offline(filename.c_str(), pcap_errbuf);
		if (!pcap)
		{
			YANET_LOG_ERROR("error: pcap_open_offline(): %s\n", pcap_errbuf);
			throw "";
		}
		memset(&header, 0, sizeof(struct pcap_pkthdr));
		advance();
	}

	pcap_expectation(pcap_expectation&& other) :
	        filename(std::move(other.filename)),
	        has_packet(other.has_packet),
	        packetsCount(other.packetsCount),
	        pcap(other.pcap),
	        buffer(other.buffer)
	{
		memcpy(&header, &other.header, sizeof(struct pcap_pkthdr));
		other.pcap = nullptr;
	}

	void advance()
	{
		if (!has_packet)
		{
			return;
		}
		pcap_pkthdr* h = nullptr;
		const u_char* data = nullptr;
		if (pcap_next_ex(pcap, &h, &data) >= 0)
		{
			memcpy(&header, h, sizeof(struct pcap_pkthdr));

			memcpy(buffer.data(), data, header.caplen);
			if (header.len > header.caplen)
			{
				memset(buffer.data() + header.caplen, 0, header.len - header.caplen);
			}

			++packetsCount;
		}
		else
		{
			has_packet = false;
		}
	}

	[[nodiscard]] bool has_unmatched_packets() const
	{
		return has_packet;
	}

	bool matches_packet(u_int packetSize, u_char* packet) const
	{
		return has_packet &&
		       header.len == packetSize &&
		       !memcmp(buffer.data(), packet, packetSize);
	}

	[[nodiscard]] std::string location() const
	{
		return filename + ":" + std::to_string(packetsCount);
	}

	[[nodiscard]] int expected_len() const
	{
		return header.len;
	}

	[[nodiscard]] const u_char* begin() const
	{
		return buffer.data();
	}

	[[nodiscard]] const u_char* end() const
	{
		return buffer.data() + header.len;
	}

	~pcap_expectation()
	{
		if (pcap)
		{
			pcap_close(pcap);
		}
	}

private:
	std::string filename;
	bool has_packet{true};
	struct pcap_pkthdr header;
	uint64_t packetsCount{};
	pcap_t* pcap;
	std::vector<u_char> buffer;
};

void tAutotest::recvThread(std::string interfaceName,
                           std::vector<std::string> expectFilePaths,
                           Duration timelimit)
{
	PcapDumper pcapDumper(std::tmpnam(nullptr) + std::string(".pcap"));

	std::vector<pcap_expectation> expect_pcaps;
	for (const auto& expectFilePath : expectFilePaths)
	{
		expect_pcaps.emplace_back(expectFilePath);
	}

	TextDumper dumper;

	if (timelimit > WARN_WAIT_THRESHOLD)
	{
		YANET_LOG_INFO("Will wait for packets for %lu seconds.\n",
		               std::chrono::duration_cast<std::chrono::seconds>(timelimit).count());
	}
	auto time_to_give_up = std::chrono::system_clock::now() + timelimit;

	auto iface = pcaps[interfaceName];
	bool success = true;
	uint64_t packetsCount = 0;
	while (std::any_of(expect_pcaps.begin(), expect_pcaps.end(), [](const auto& expectation) { return expectation.has_unmatched_packets(); }))
	{
		u_char buffer[MAX_PACK_LEN];
		pcap_pkthdr tmp_pcap_packetHeader;

		auto now = std::chrono::system_clock::now();
		if (now > time_to_give_up)
		{
			YANET_LOG_ERROR("error[%s]: step time limit exceeded\n", interfaceName.data());
			throw "";
		}
		if (!readPacket(iface, &tmp_pcap_packetHeader, buffer, time_to_give_up - now))
		{
			std::stringstream buf;
			bool not_first = false;
			for (const auto& expectation : expect_pcaps)
			{
				if (expectation.has_unmatched_packets())
				{
					if (not_first)
					{
						buf << " or ";
					}
					buf << expectation.location();
					not_first = true;
				}
			}
			YANET_LOG_ERROR("error[%s]: miss packet %lu from:(%s)\n",
			                interfaceName.data(),
			                packetsCount + 1,
			                buf.str().data());

			YANET_LOG_ERROR("pcap[%s]: %s\n",
			                interfaceName.data(),
			                pcapDumper.path().data());

			throw "";
		}

		if (dumpPackets)
		{
			pcapDumper.dump(&tmp_pcap_packetHeader, buffer);
		}

		auto packetSize = tmp_pcap_packetHeader.len;
		bool found = false;
		for (auto& expectation : expect_pcaps)
		{
			if (expectation.matches_packet(packetSize, buffer))
			{
				expectation.advance();
				found = true;
				break;
			}
		}
		if (!found)
		{
			std::stringstream buf;
			bool not_first = false;
			for (const auto& expectation : expect_pcaps)
			{
				if (expectation.has_unmatched_packets())
				{
					if (not_first)
					{
						buf << " or ";
					}
					buf << expectation.location();
					not_first = true;
				}
			}
			YANET_LOG_ERROR("error[%s]: wrong packet #%lu. expected (%s)\n",
			                interfaceName.data(),
			                packetsCount + 1,
			                buf.str().c_str());

			if (dumpPackets)
			{
				int n = std::count_if(expect_pcaps.begin(), expect_pcaps.end(), [](const auto& expectation) { return expectation.has_unmatched_packets(); });
				int i = 1;
				for (const auto& expectation : expect_pcaps)
				{
					if (!expectation.has_unmatched_packets())
					{
						continue;
					}
					YANET_LOG_DEBUG("Expectation (%d/%d) expected %u, got %u\n", i, n, expectation.expected_len(), packetSize);
					dumper.dump(expectation.begin(), expectation.end(), buffer, buffer + packetSize);
					++i;
				}
			}
			success = false;

			if (expect_pcaps.size() == 1)
			{
				expect_pcaps[0].advance();
			}
		}

		packetsCount++;
	}

	for (;;)
	{
		u_char buffer[MAX_PACK_LEN];
		pcap_pkthdr tmp_pcap_packetHeader;

		if (!readPacket(iface, &tmp_pcap_packetHeader, buffer, DEFAULT_PACKET_READ_TIME_LIMIT))
		{
			break;
		}

		if (dumpPackets)
		{
			pcapDumper.dump(&tmp_pcap_packetHeader, buffer);

			auto packetSize = tmp_pcap_packetHeader.len;
			YANET_LOG_DEBUG("unexpected %u\n", packetSize);
			dumper.dump(nullptr, nullptr, buffer, buffer + packetSize);
		}

		success = false;

		packetsCount++;
	}

	YANET_LOG_DEBUG("recv %lu packets\n", packetsCount);

	if (!success)
	{
		YANET_LOG_ERROR("error[%s]: unknown packet\n", interfaceName.data());
		YANET_LOG_ERROR("pcap[%s]: %s\n",
		                interfaceName.data(),
		                pcapDumper.path().data());

		throw "";
	}

	unlink(pcapDumper.path().data());
}

bool tAutotest::step_ipv4Update(const YAML::Node& yamlStep)
{
	if (yamlStep.IsScalar())
	{
		convert_ipv4Update(yamlStep.as<std::string>());
	}
	else
	{
		for (const auto& yamlRoute : yamlStep)
		{
			convert_ipv4Update(yamlRoute.as<std::string>());
		}
	}

	return true;
}

bool tAutotest::step_ipv4Remove(const YAML::Node& yamlStep)
{
	if (yamlStep.IsScalar())
	{
		convert_ipv4Remove(yamlStep.as<std::string>());
	}
	else
	{
		for (const auto& yamlRoute : yamlStep)
		{
			convert_ipv4Remove(yamlRoute.as<std::string>());
		}
	}

	return true;
}

bool tAutotest::step_ipv4LabelledUpdate(const YAML::Node& yamlStep)
{
	if (yamlStep.IsScalar())
	{
		convert_ipv4LabelledUpdate(yamlStep.as<std::string>());
	}
	else
	{
		for (const auto& yamlRoute : yamlStep)
		{
			convert_ipv4LabelledUpdate(yamlRoute.as<std::string>());
		}
	}

	return true;
}

bool tAutotest::step_ipv4LabelledRemove(const YAML::Node& yamlStep)
{
	if (yamlStep.IsScalar())
	{
		convert_ipv4LabelledRemove(yamlStep.as<std::string>());
	}
	else
	{
		for (const auto& yamlRoute : yamlStep)
		{
			convert_ipv4LabelledRemove(yamlRoute.as<std::string>());
		}
	}

	return true;
}

bool tAutotest::step_ipv6Update(const YAML::Node& yamlStep)
{
	if (yamlStep.IsScalar())
	{
		convert_ipv6Update(yamlStep.as<std::string>());
	}
	else
	{
		for (const auto& yamlRoute : yamlStep)
		{
			convert_ipv6Update(yamlRoute.as<std::string>());
		}
	}

	return true;
}

bool tAutotest::step_ipv6LabelledUpdate(const YAML::Node& yamlStep)
{
	if (yamlStep.IsScalar())
	{
		convert_ipv6LabelledUpdate(yamlStep.as<std::string>());
	}
	else
	{
		for (const auto& yamlRoute : yamlStep)
		{
			convert_ipv6LabelledUpdate(yamlRoute.as<std::string>());
		}
	}

	return true;
}

bool tAutotest::step_checkCounters(const YAML::Node& yamlStep)
{
	std::map<uint32_t, uint64_t> expected;

	for (const auto& yamlCounter : yamlStep)
	{
		expected[yamlCounter.first.as<uint32_t>()] = yamlCounter.second.as<uint64_t>();
	}

	std::map<uint32_t, uint64_t> counters;
	auto fwList = controlPlane.getFwList(common::icp::getFwList::requestType::static_rules_original);
	for (auto& [ruleno, rules] : fwList)
	{
		GCC_BUG_UNUSED(ruleno);
		for (auto& [id, counter, text] : rules)
		{
			GCC_BUG_UNUSED(text);
			counters[id] = counter;
		}
	}

	EXPECT_THAT(counters, ::testing::ContainerEq(expected));

	return true;
}

bool tAutotest::step_sendPackets(const YAML::Node& yamlStep,
                                 const std::string& path)
{
	std::vector<std::thread> threads;

	bool success = true;

	for (const auto& yamlPort : yamlStep)
	{
		auto interfaceName = yamlPort["port"].as<std::string>();

		if (yamlPort["send"])
		{
			std::string sendFilePath = path + "/" + yamlPort["send"].as<std::string>();

			threads.emplace_back([this, &success, interfaceName, sendFilePath]() {
				try
				{
					sendThread(interfaceName, sendFilePath);
				}
				catch (...)
				{
					success = false;
				}
			});
		}

		if (yamlPort["dump"])
		{
			std::string dumpFilePath = path + "/" + yamlPort["dump"].as<std::string>();

			threads.emplace_back([this, &success, interfaceName, dumpFilePath]() {
				try
				{
					dumpThread(interfaceName, dumpFilePath);
				}
				catch (...)
				{
					success = false;
				}
			});
		}
		else
		{
			auto& yamlExpect = yamlPort["expect"];
			std::vector<std::string> paths;
			if (yamlExpect.IsSequence())
			{
				for (const auto& yamlPath : yamlExpect)
				{
					paths.push_back(path + "/" + yamlPath.as<std::string>());
				}
			}
			else
			{
				// scalar
				paths.push_back(path + "/" + yamlExpect.as<std::string>());
			}

			Duration timelimit = DEFAULT_STEP_TIME_LIMIT;
			auto& yamlTimelimit = yamlPort["timelimit"];
			if (yamlTimelimit)
			{
				using namespace std::chrono;
				timelimit = duration_cast<Duration>(seconds{yamlTimelimit.as<unsigned int>()});
			}

			threads.emplace_back([this, &success, interfaceName, paths, timelimit]() {
				try
				{
					recvThread(interfaceName, paths, timelimit);
				}
				catch (...)
				{
					success = false;
				}
			});
		}
	}

	for (auto& thread : threads)
	{
		if (thread.joinable())
		{
			thread.join();
		}
	}

	if (!success)
	{
		throw "";
	}

	return true;
}

bool tAutotest::step_sleep(const YAML::Node& yamlStep)
{
	if (yamlStep.IsScalar())
	{
		sleep(yamlStep.as<unsigned int>());
	}

	return true;
}

bool tAutotest::step_rib_insert(const YAML::Node& yaml)
{
	common::icp::rib_update::insert request = {"autotest", YANET_RIB_VRF_DEFAULT, YANET_RIB_PRIORITY_DEFAULT, {}};
	auto& [protocol, vrf, priority, attribute_tables] = request;

	if (yaml["attribute"].IsDefined())
	{
		const auto& yaml_attribute = yaml["attribute"];

		if (yaml_attribute["protocol"].IsDefined())
		{
			protocol = yaml_attribute["protocol"].as<std::string>();
		}

		if (yaml_attribute["vrf"].IsDefined())
		{
			vrf = yaml_attribute["vrf"].as<std::string>();
		}

		if (yaml_attribute["priority"].IsDefined())
		{
			priority = yaml_attribute["priority"].as<uint32_t>();
		}
	}

	if (yaml["tables"].IsDefined())
	{
		for (const auto& yaml_table : yaml["tables"])
		{
			std::string table_name = "";
			if (yaml_table["table_name"].IsDefined())
			{
				table_name = yaml_table["table_name"].as<std::string>();
			}

			std::string peer = "0.0.0.0";
			if (yaml_table["peer"].IsDefined())
			{
				peer = yaml_table["peer"].as<std::string>();
			}

			uint32_t med = 0;
			if (yaml_table["med"].IsDefined())
			{
				med = yaml_table["med"].as<uint32_t>();
			}

			std::vector<uint32_t> aspath;
			if (yaml_table["aspath"].IsDefined())
			{
				for (const auto& yaml_aspath : yaml_table["aspath"])
				{
					aspath.emplace_back(yaml_aspath.as<uint32_t>());
				}
			}

			std::set<community_t> communities;
			if (yaml_table["communities"].IsDefined())
			{
				for (const auto& yaml_community : yaml_table["communities"])
				{
					communities.emplace(yaml_community.as<std::string>());
				}
			}

			std::set<large_community_t> large_communities;
			if (yaml_table["large_communities"].IsDefined())
			{
				for (const auto& yaml_large_community : yaml_table["large_communities"])
				{
					large_communities.emplace(yaml_large_community.as<std::string>());
				}
			}

			uint32_t local_pref = 0;
			if (yaml_table["local_pref"].IsDefined())
			{
				local_pref = yaml_table["local_pref"].as<uint32_t>();
			}

			auto& prefixes = attribute_tables[{peer, "incomplete", med, aspath, communities, large_communities, local_pref}][table_name];

			if (yaml_table["prefixes"].IsDefined())
			{
				for (const auto& yaml_prefix : yaml_table["prefixes"])
				{
					ip_address_t nexthop = yaml_prefix["nexthop"].as<std::string>();
					ip_prefix_t prefix = yaml_prefix["prefix"].as<std::string>();

					std::string path_information;
					if (yaml_prefix["path_information"].IsDefined())
					{
						path_information = yaml_prefix["path_information"].as<std::string>();
					}

					std::vector<uint32_t> labels;
					if (yaml_prefix["labels"].IsDefined())
					{
						for (const auto& yaml_label : yaml_prefix["labels"])
						{
							labels.emplace_back(yaml_label.as<uint32_t>());
						}
					}

					prefixes[nexthop].emplace_back(prefix, path_information, labels);
				}
			}
		}
	}

	controlPlane.rib_update({request});
	controlPlane.rib_flush();

	return true;
}

bool tAutotest::step_rib_remove(const YAML::Node& yaml)
{
	common::icp::rib_update::remove request = {"autotest", YANET_RIB_VRF_DEFAULT, YANET_RIB_PRIORITY_DEFAULT, {}};
	auto& [protocol, vrf, priority, tables] = request;

	if (yaml["attribute"].IsDefined())
	{
		const auto& yaml_attribute = yaml["attribute"];

		if (yaml_attribute["protocol"].IsDefined())
		{
			protocol = yaml_attribute["protocol"].as<std::string>();
		}

		if (yaml_attribute["vrf"].IsDefined())
		{
			vrf = yaml_attribute["vrf"].as<std::string>();
		}

		if (yaml_attribute["priority"].IsDefined())
		{
			priority = yaml_attribute["priority"].as<uint32_t>();
		}
	}

	if (yaml["tables"].IsDefined())
	{
		for (const auto& yaml_table : yaml["tables"])
		{
			std::string table_name = "";
			if (yaml_table["table_name"].IsDefined())
			{
				table_name = yaml_table["table_name"].as<std::string>();
			}

			std::string peer = "0.0.0.0";
			if (yaml_table["peer"].IsDefined())
			{
				peer = yaml_table["peer"].as<std::string>();
			}

			if (yaml_table["prefixes"].IsDefined())
			{
				for (const auto& yaml_prefix : yaml_table["prefixes"])
				{
					ip_prefix_t prefix = yaml_prefix["prefix"].as<std::string>();

					std::string path_information;
					if (yaml_prefix["path_information"].IsDefined())
					{
						path_information = yaml_prefix["path_information"].as<std::string>();
					}

					std::vector<uint32_t> labels;
					if (yaml_prefix["labels"].IsDefined())
					{
						for (const auto& yaml_label : yaml_prefix["labels"])
						{
							labels.emplace_back(yaml_label.as<uint32_t>());
						}
					}

					tables[peer][table_name].emplace_back(prefix, path_information, labels);
				}
			}
		}
	}

	controlPlane.rib_update({request});
	controlPlane.rib_flush();

	return true;
}

bool tAutotest::step_rib_clear(const YAML::Node& yaml)
{
	common::icp::rib_update::clear request = {"autotest", std::nullopt};
	auto& [protocol, peer_vrf_priority] = request;

	if (yaml["attribute"].IsDefined())
	{
		const auto& yaml_attribute = yaml["attribute"];

		if (yaml_attribute["protocol"].IsDefined())
		{
			protocol = yaml_attribute["protocol"].as<std::string>();
		}

		if (yaml_attribute["peer"].IsDefined() && yaml_attribute["vrf"].IsDefined() && yaml_attribute["priority"].IsDefined())
		{
			auto peer = yaml_attribute["peer"].as<std::string>();
			auto vrf = yaml_attribute["vrf"].as<std::string>();
			auto priority = yaml_attribute["priority"].as<uint32_t>();

			std::tuple<std::string, uint32_t> vrf_priority_tup(std::move(vrf), std::move(priority));
			std::tuple<ip_address_t, std::tuple<std::string, uint32_t>> peer_vrf_priority_tup(std::move(peer), std::move(vrf_priority_tup));

			peer_vrf_priority.emplace(std::move(peer_vrf_priority_tup));
		}
	}

	controlPlane.rib_update({request});
	controlPlane.rib_flush();

	return true;
}

namespace
{
auto replaceAll(std::string s, const std::string& from, const std::string& to)
{
	size_t pos = s.find(from);
	while (pos != std::string::npos)
	{
		s.replace(pos, from.size(), to);
		pos = s.find(s, pos + to.size());
	}

	return s;
}
}

bool tAutotest::step_cli(const YAML::Node& yamlStep, const std::string& path)
{
	if (yamlStep.IsScalar())
	{
		if (cli(replaceAll(yamlStep.as<std::string>(), "TESTDIR", path)) != 0)
		{
			return false;
		}
	}
	else
	{
		for (const auto& yamlIter : yamlStep)
		{
			if (cli(replaceAll(yamlIter.as<std::string>(), "TESTDIR", path)) != 0)
			{
				return false;
			}
		}
	}

	return true;
}

bool tAutotest::step_clearFWState()
{
	controlPlane.clearFWState();

	return true;
}

bool has_suffix(const std::string& string,
                const std::string& suffix)
{
	return string.size() >= suffix.size() &&
	       string.compare(string.size() - suffix.size(), suffix.size(), suffix) == 0;
}

static common::icp::loadConfig::request prepareLoadConfig(std::string configFilePath, std::string name)
{

#ifdef __cpp_lib_filesystem
	namespace fs = std::filesystem;
#else
	namespace fs = std::experimental::filesystem;
#endif

	common::icp::loadConfig::request request;

	std::ifstream fromFileStream(fs::path(configFilePath).append(name));

	std::get<0>(request) = fs::path(configFilePath).append(name);
	std::get<1>(request) = std::string((std::istreambuf_iterator<char>(fromFileStream)), std::istreambuf_iterator<char>());

	for (const auto& entry : fs::directory_iterator(configFilePath))
	{
		if (has_suffix(entry.path().string(), ".conf"))
		{
			std::ifstream confFileStream(entry.path().string());
			std::get<2>(request)[entry.path().string()] = std::string((std::istreambuf_iterator<char>(confFileStream)), std::istreambuf_iterator<char>());
		}
	}

	if (fs::is_directory(configFilePath + "/virtualfs"))
	{
		/// @todo: recursive_directory_iterator
		for (const auto& entry : fs::directory_iterator(configFilePath + "/virtualfs"))
		{
			if (has_suffix(entry.path().string(), ".conf"))
			{
				std::ifstream confFileStream(entry.path().string());
				std::get<2>(request)["/virtualfs/" + entry.path().filename().string()] = std::string((std::istreambuf_iterator<char>(confFileStream)), std::istreambuf_iterator<char>());
			}
		}
	}

	return request;
}

void tAutotest::mainThread()
{
#ifdef __cpp_lib_filesystem
	namespace fs = std::filesystem;
#else
	namespace fs = std::experimental::filesystem;
#endif

	for (const auto& configFilePath : configFilePaths)
	{
		YANET_LOG_PRINT(ANSI_COLOR_YELLOW "\nrun '%s'\n" ANSI_COLOR_RESET, configFilePath.data());
		fflush(stdout);
		fflush(stderr);

		fflushSharedMemory();

		/// clear dataplane states
		{
			dataPlane.balancer_state_clear();
			dataPlane.neighbor_clear();
		}

		try
		{
			{
				configFilePath_current = configFilePath;

				common::icp::loadConfig::request request = prepareLoadConfig(configFilePath, "controlplane.conf");

				controlPlane.rib_update({common::icp::rib_update::clear("autotest", std::nullopt)});
				controlPlane.rib_flush();

				const auto result = controlPlane.loadConfig(request);
				if (result != eResult::success)
				{
					YANET_LOG_ERROR("invalid config: eResult %d\n", static_cast<std::uint32_t>(result));
					throw "";
				}
				controlPlane.rib_flush();

				this->request.swap(request);
			}

			dataPlane.neighbor_flush();

			YAML::Node yamlRoot = YAML::LoadFile(configFilePath + "/autotest.yaml");

			for (const YAML::Node& yamlStep : yamlRoot["steps"])
			{
				bool result = true;

				if (yamlStep["subtest"])
				{
					auto test_name = yamlStep["subtest"].as<std::string>();
					YANET_LOG_PRINT(ANSI_COLOR_BLUE "Running subtest: '%s'\n" ANSI_COLOR_RESET, test_name.c_str());
				}
				else if (yamlStep["ipv4Update"])
				{
					YANET_LOG_DEBUG("step: ipv4Update\n");

					result = step_ipv4Update(yamlStep["ipv4Update"]);
				}
				else if (yamlStep["ipv4Remove"])
				{
					YANET_LOG_DEBUG("step: ipv4Remove\n");

					result = step_ipv4Remove(yamlStep["ipv4Remove"]);
				}
				else if (yamlStep["ipv4LabelledUpdate"])
				{
					YANET_LOG_DEBUG("step: ipv4LabelledUpdate\n");

					result = step_ipv4LabelledUpdate(yamlStep["ipv4LabelledUpdate"]);
				}
				else if (yamlStep["ipv4LabelledRemove"])
				{
					YANET_LOG_DEBUG("step: ipv4LabelledRemove\n");

					result = step_ipv4LabelledRemove(yamlStep["ipv4LabelledRemove"]);
				}
				else if (yamlStep["ipv6Update"])
				{
					YANET_LOG_DEBUG("step: ipv6Update\n");

					result = step_ipv6Update(yamlStep["ipv6Update"]);
				}
				else if (yamlStep["ipv6LabelledUpdate"])
				{
					YANET_LOG_DEBUG("step: ipv6LabelledUpdate\n");

					result = step_ipv6LabelledUpdate(yamlStep["ipv6LabelledUpdate"]);
				}
				else if (yamlStep["checkCounters"])
				{
					YANET_LOG_DEBUG("step: checkCounters\n");

					result = step_checkCounters(yamlStep["checkCounters"]);
				}
				else if (yamlStep["sendPackets"])
				{
					YANET_LOG_DEBUG("step: sendPackets\n");

					result = step_sendPackets(yamlStep["sendPackets"],
					                          configFilePath);
				}
				else if (yamlStep["sleep"])
				{
					YANET_LOG_DEBUG("step: sleep\n");

					result = step_sleep(yamlStep["sleep"]);
				}
				else if (yamlStep["rib_insert"])
				{
					YANET_LOG_DEBUG("step: rib_insert\n");

					result = step_rib_insert(yamlStep["rib_insert"]);
				}
				else if (yamlStep["rib_remove"])
				{
					YANET_LOG_DEBUG("step: rib_remove\n");

					result = step_rib_remove(yamlStep["rib_remove"]);
				}
				else if (yamlStep["rib_clear"])
				{
					YANET_LOG_DEBUG("step: rib_clear\n");

					result = step_rib_clear(yamlStep["rib_clear"]);
				}
				else if (yamlStep["cli"])
				{
					YANET_LOG_DEBUG("step: cli\n");

					result = step_cli(yamlStep["cli"], configFilePath);
				}
				else if (yamlStep["clearFWState"])
				{
					YANET_LOG_DEBUG("step: clearFWState\n");

					result = step_clearFWState();
				}
				else if (yamlStep["reload"])
				{
					YANET_LOG_DEBUG("step: reload\n");

					result = step_reload(yamlStep["reload"]);
				}
				else if (yamlStep["values"])
				{
					YANET_LOG_DEBUG("step: values\n");

					result = step_values(yamlStep["values"]);
				}
				else if (yamlStep["cli_check"])
				{
					YANET_LOG_DEBUG("step: cli_check\n");

					result = step_cli_check(yamlStep["cli_check"]);
				}
				else if (yamlStep["reload_async"])
				{
					YANET_LOG_DEBUG("step: reload_async\n");

					result = step_reload_async(yamlStep["reload_async"]);
				}
				else if (yamlStep["memorize_counter_value"])
				{
					YANET_LOG_DEBUG("step: memorize_counter_value\n");

					result = step_memorize_counter_value(yamlStep["memorize_counter_value"]);
				}
				else if (yamlStep["diff_with_kept_counter_value"])
				{
					YANET_LOG_DEBUG("step: diff_with_kept_counter_value\n");

					result = step_diff_with_kept_counter_value(yamlStep["diff_with_kept_counter_value"]);
				}
				else if (yamlStep["echo"])
				{
					YANET_LOG_DEBUG("step: echo\n");

					result = step_echo(yamlStep["echo"]);
				}
				else if (yamlStep["dumpPackets"])
				{
					YANET_LOG_DEBUG("step: dumpPackets\n");

					result = step_dumpPackets(yamlStep["dumpPackets"], configFilePath);
				}
				else
				{
					YANET_LOG_ERROR("unknown step\n");
					throw "";
				}

				if (!result)
				{
					throw "";
				}
			}
		}
		catch (...)
		{
			YANET_LOG_PRINT(ANSI_COLOR_RED "fail '%s'\n\n" ANSI_COLOR_RESET, configFilePath.data());
			fflush(stdout);
			fflush(stderr);

			std::ofstream out("/tmp/yanet-dp.report");
			out << dataPlane.getReport();

			std::abort();
		}

		YANET_LOG_PRINT(ANSI_COLOR_GREEN "done '%s'\n\n" ANSI_COLOR_RESET, configFilePath.data());
		fflush(stdout);
		fflush(stderr);
	}

	std::ofstream out("/tmp/yanet-dp.report");
	out << dataPlane.getReport();
}

void tAutotest::convert_ipv4Update(const std::string& string)
{
	std::string prefix = string.substr(0, string.find(" -> "));
	std::string nexthops = string.substr(string.find(" -> ") + 4);

	convert_ipv4Remove(prefix);

	for (const auto& nexthop : utils::split(nexthops, ' '))
	{
		common::icp::rib_update::insert request = {"autotest", YANET_RIB_VRF_DEFAULT, YANET_RIB_PRIORITY_DEFAULT, {}};
		std::get<3>(request)[attribute_default]["ipv4"][nexthop].emplace_back(prefix,
		                                                                      std::to_string(pathInformations_ipv4Update[prefix].size()),
		                                                                      std::vector<uint32_t>());
		controlPlane.rib_update({request});

		pathInformations_ipv4Update[prefix].emplace(std::to_string(pathInformations_ipv4Update[prefix].size()));
	}

	controlPlane.rib_flush();
}

void tAutotest::convert_ipv4Remove(const std::string& string)
{
	for (const auto& pathInformation : pathInformations_ipv4Update[string])
	{
		common::icp::rib_update::remove request = {"autotest", YANET_RIB_VRF_DEFAULT, YANET_RIB_PRIORITY_DEFAULT, {}};
		std::get<3>(request)[{}]["ipv4"].emplace_back(ip_prefix_t(string),
		                                              pathInformation,
		                                              std::vector<uint32_t>());
		controlPlane.rib_update({request});
	}

	pathInformations_ipv4Update[string].clear();

	controlPlane.rib_flush();
}

void tAutotest::convert_ipv4LabelledUpdate(const std::string& string)
{
	std::string prefix = string.substr(0, string.find(" -> "));
	std::string nexthops = string.substr(string.find(" -> ") + 4);

	convert_ipv4LabelledRemove(prefix);

	for (const auto& nexthop_label : utils::split(nexthops, ' '))
	{
		std::string nexthop = nexthop_label.substr(0, nexthop_label.find(":"));
		std::string label = nexthop_label.substr(nexthop_label.find(":") + 1);

		std::vector<uint32_t> labels;
		labels.emplace_back(std::stoll(label, nullptr, 0));

		common::icp::rib_update::insert request = {"autotest", YANET_RIB_VRF_DEFAULT, YANET_RIB_PRIORITY_DEFAULT, {}};
		std::get<3>(request)[attribute_default]["ipv4 mpls"][nexthop].emplace_back(prefix,
		                                                                           std::to_string(pathInformations_ipv4LabelledUpdate[prefix].size()) + ":10001",
		                                                                           labels);
		controlPlane.rib_update({request});

		pathInformations_ipv4LabelledUpdate[prefix].emplace(std::to_string(pathInformations_ipv4LabelledUpdate[prefix].size()) + ":10001");
	}

	controlPlane.rib_flush();
}

void tAutotest::convert_ipv4LabelledRemove(const std::string& string)
{
	std::vector<uint32_t> labels;
	labels.emplace_back(0);

	for (const auto& pathInformation : pathInformations_ipv4LabelledUpdate[string])
	{
		common::icp::rib_update::remove request = {"autotest", YANET_RIB_VRF_DEFAULT, YANET_RIB_PRIORITY_DEFAULT, {}};
		std::get<3>(request)[{}]["ipv4 mpls"].emplace_back(ip_prefix_t(string),
		                                                   pathInformation,
		                                                   labels);
		controlPlane.rib_update({request});
	}

	pathInformations_ipv4LabelledUpdate[string].clear();

	controlPlane.rib_flush();
}

void tAutotest::convert_ipv6Update(const std::string& string)
{
	std::string prefix = string.substr(0, string.find(" -> "));
	std::string nexthops = string.substr(string.find(" -> ") + 4);

	for (const auto& nexthop : utils::split(nexthops, ' '))
	{
		common::icp::rib_update::insert request = {"autotest", YANET_RIB_VRF_DEFAULT, YANET_RIB_PRIORITY_DEFAULT, {}};
		std::get<3>(request)[attribute_default]["ipv6"][nexthop].emplace_back(prefix,
		                                                                      nexthop,
		                                                                      std::vector<uint32_t>());
		controlPlane.rib_update({request});
	}

	controlPlane.rib_flush();
}

void tAutotest::convert_ipv6LabelledUpdate(const std::string& string)
{
	std::string prefix = string.substr(0, string.find(" -> "));
	std::string nexthops = string.substr(string.find(" -> ") + 4);

	for (const auto& nexthop_label : utils::split(nexthops, ' '))
	{
		std::string nexthop = nexthop_label.substr(0, nexthop_label.find("|"));
		std::string label = nexthop_label.substr(nexthop_label.find("|") + 1);

		std::vector<uint32_t> labels;
		labels.emplace_back(std::stoll(label, nullptr, 0));

		common::icp::rib_update::insert request = {"autotest", YANET_RIB_VRF_DEFAULT, YANET_RIB_PRIORITY_DEFAULT, {}};
		std::get<3>(request)[attribute_default]["ipv6 mpls"][nexthop].emplace_back(prefix,
		                                                                           label + ":10001", ///< @todo: nexthop_label
		                                                                           labels);
		controlPlane.rib_update({request});
	}

	controlPlane.rib_flush();
}

int tAutotest::cli(const std::string& command)
{
	std::string cli_command = "yanet-cli " + command;
	YANET_LOG_DEBUG("%s\n", cli_command.data());
	return system(cli_command.data());
}

bool nAutotest::tAutotest::step_reload(const YAML::Node& yamlStep)
{
	common::icp::loadConfig::request request = prepareLoadConfig(configFilePath_current, yamlStep.as<std::string>());

	const auto result = controlPlane.loadConfig(request);
	if (result != eResult::success)
	{
		YANET_LOG_ERROR("invalid config: eResult %d\n", static_cast<std::uint32_t>(result));
		return false;
	}
	controlPlane.rib_flush();

	this->request.swap(request);

	return true;
}

bool nAutotest::tAutotest::step_reload_async(const YAML::Node& yamlStep)
{
	common::icp::loadConfig::request request = prepareLoadConfig(configFilePath_current, yamlStep.as<std::string>());

	pid_t pid = fork();

	if (pid == 0)
	{
		interface::controlPlane controlPlane;
		const auto result = controlPlane.loadConfig(request);
		if (result != eResult::success)
		{
			YANET_LOG_ERROR("invalid config: eResult %d\n", static_cast<std::uint32_t>(result));
		}
		exit(0);
	}

	if (pid < 0)
	{
		YANET_LOG_ERROR("could not fork for asynchronous update\n");
		return false;
	}

	return true;
}

bool tAutotest::step_values(const YAML::Node& yamlStep)
{
	const auto values = controlPlane.controlplane_values();

	std::set<std::string> values_set;
	for (const auto& [name, value] : values)
	{
		std::string string = "controlplane " + name + " " + value;
		values_set.emplace(string);
		YANET_LOG_DEBUG("%s\n", string.data());
	}

	if (yamlStep.IsScalar())
	{
		if (!exist(values_set, yamlStep.as<std::string>()))
		{
			YANET_LOG_ERROR("invalid: %s\n", yamlStep.as<std::string>().data());
			return false;
		}
	}
	else
	{
		for (const auto& yamlIter : yamlStep)
		{
			if (!exist(values_set, yamlIter.as<std::string>()))
			{
				YANET_LOG_ERROR("invalid: %s\n", yamlIter.as<std::string>().data());
				return false;
			}
		}
	}

	return true;
}

bool tAutotest::step_memorize_counter_value(const YAML::Node& yamlStep)
{
	uint64_t delim_pos = yamlStep.as<std::string>().find(' ');

	if (delim_pos == std::string::npos)
	{
		return false;
	}

	std::string counter_name = yamlStep.as<std::string>().substr(0, delim_pos);

	uint32_t coreId = std::stoi(yamlStep.as<std::string>().substr(delim_pos + 1));

	const auto response = common::sdp::SdpClient::GetCounterByName(sdp_data, counter_name, coreId);

	if (response.empty())
	{
		YANET_LOG_ERROR("  no counter with name %s for coreId %u\n", counter_name.data(), coreId);
		return false;
	}

	memorized_counter_name = counter_name;
	memorized_coreId = coreId;
	memorized_counter_value = response.at(coreId);

	return true;
}

bool tAutotest::step_diff_with_kept_counter_value(const YAML::Node& yamlStep)
{
	if (memorized_counter_name.empty())
	{
		YANET_LOG_ERROR("  no counter was previously memorized: nothing to compare with\n");
		return false;
	}

	uint64_t first_delim_pos = yamlStep.as<std::string>().find(' ');

	if (first_delim_pos == std::string::npos)
	{
		YANET_LOG_ERROR("  format error, expected format: [counter_name] [core_id] [expected_diff_value]\n");
		return false;
	}

	std::string counter_name = yamlStep.as<std::string>().substr(0, first_delim_pos);

	if (counter_name != memorized_counter_name)
	{
		YANET_LOG_ERROR("  cannot make a diff for different counters (%s is memorized, %s is provided in this step)\n",
		                memorized_counter_name.data(),
		                counter_name.data());
		return false;
	}

	uint64_t second_delim_pos = yamlStep.as<std::string>().find(' ', first_delim_pos + 1);

	if (second_delim_pos == std::string::npos)
	{
		YANET_LOG_ERROR("  format error, expected format: [counter_name] [core_id] [expected_diff_value]\n");
		return false;
	}

	uint32_t coreId = std::stoi(yamlStep.as<std::string>().substr(first_delim_pos + 1, second_delim_pos));

	if (coreId != memorized_coreId)
	{
		YANET_LOG_ERROR("  cannot make a diff for counters of different coreIds (%u coreId is memorized, %u coreId is provided in this step)\n",
		                memorized_coreId,
		                coreId);
		return false;
	}

	const auto response = common::sdp::SdpClient::GetCounterByName(sdp_data, counter_name, coreId);

	if (response.empty())
	{
		YANET_LOG_ERROR("  no counter with name %s for coreId %u\n", counter_name.data(), coreId);
		return false;
	}

	uint64_t current_counter_value = response.at(coreId);
	uint64_t expected_diff = std::stoi(yamlStep.as<std::string>().substr(second_delim_pos + 1));
	uint64_t actual_diff = current_counter_value - memorized_counter_value;

	if (expected_diff != actual_diff)
	{
		YANET_LOG_ERROR("  expected:\n%lu\n  got:\n%lu\n", expected_diff, actual_diff);

		return false;
	}

	memorized_counter_name = ""; // refresh indicator: nothing is currently memorized

	return true;
}

bool tAutotest::step_echo(const YAML::Node& yamlStep)
{
	if (yamlStep.IsScalar())
	{
		printf("%s\n", yamlStep.as<std::string>().data());
	}
	else
	{
		for (const auto& yamlIter : yamlStep)
		{
			printf("%s\n", yamlIter.as<std::string>().data());
		}
	}

	return true;
}

std::string exec(const char* cmd)
{
	char buffer[128];
	std::string result = "";

	FILE* pipe = popen(cmd, "r");
	if (!pipe)
	{
		throw std::runtime_error("popen() failed!");
	}

	try
	{
		while (fgets(buffer, sizeof buffer, pipe) != nullptr)
		{
			result += buffer;
		}
	}
	catch (...)
	{
		pclose(pipe);
		throw;
	}

	pclose(pipe);
	return result;
}

bool tAutotest::step_cli_check(const YAML::Node& yamlStep)
{
	std::string first_line = yamlStep.as<std::string>().substr(0, yamlStep.as<std::string>().find('\n'));
	std::string command;

	// TODO: what if there are multiple YANET_* env variables?
	uint64_t env_vars_pos = first_line.find("YANET");
	if (env_vars_pos != std::string::npos)
	{
		uint32_t space_pos = first_line.find(' ', env_vars_pos);
		std::string env_vars = first_line.substr(env_vars_pos, space_pos - env_vars_pos + 1);

		command = env_vars + "yanet-cli " + first_line.substr(space_pos + 1);
	}
	else
	{
		command = "yanet-cli " + first_line;
	}

	std::string check_output = yamlStep.as<std::string>().substr(yamlStep.as<std::string>().find('\n') + 1);

	std::string output = exec(command.data());
	if (output != check_output)
	{
		YANET_LOG_ERROR("  expected:\n%s\n  got:\n%s\n", check_output.data(), output.data());
		return false;
	}

	return true;
}

common::PacketBufferRing::item_t* read_shm_packet(common::PacketBufferRing* buffer, uint64_t position)
{
	common::PacketBufferRing::ring_t* ring = buffer->ring;

	if (position >= ring->header.after)
	{
		return nullptr;
	}

	return utils::ShiftBuffer<common::PacketBufferRing::item_t*>(ring->memory, position * buffer->unit_size);
}

bool tAutotest::step_dumpPackets(const YAML::Node& yamlStep,
                                 const std::string& path)
{
	TextDumper dumper;
	for (const auto& yamlDump : yamlStep)
	{
		auto tag = yamlDump["ringTag"].as<std::string>();
		std::string expectFilePath = path + "/" + yamlDump["expect"].as<std::string>();
		bool success = true;

		common::PacketBufferRing* ring = nullptr;
		{ /// searching memory ring by tag
			auto it = dumpRings.find(tag);
			if (it == dumpRings.end())
			{
				YANET_LOG_ERROR("dump [%s]: error: dump ring not found\n", tag.data());
				throw "";
			}
			// TODO: THIS IS TEMPORARY for now.
			// I want to test that the original logic is unchanged.
			// Therefore we get the internal buffer with this crude way
			// since I'm sure that DumpRing is RingRaw.
			ring = &(static_cast<dumprings::RingRaw*>(it->second.get())->buffer_);
		}

		// Open pcap file using PcapPlusPlus
		pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(expectFilePath);
		if (reader == nullptr)
		{
			YANET_LOG_ERROR("dump [%s]: error: cannot create pcap reader for file %s", tag.data(), expectFilePath.data());
			return false;
		}

		if (!reader->open())
		{
			YANET_LOG_ERROR("dump [%s]: error: cannot open pcap file %s", tag.data(), expectFilePath.data());
			return false;
		}

		pcpp::RawPacket expected_pkt;
		uint32_t pcap_packet_len = 0;
		const u_char* pcap_packet = nullptr;
		common::PacketBufferRing::item_t* shm_packet = nullptr;
		uint64_t position = 0;

		/// read packets from pcap and compare them with packets from memory ring
		while (reader->getNextPacket(expected_pkt))
		{
			shm_packet = read_shm_packet(ring, position);
			position++;

			pcap_packet_len = expected_pkt.getRawDataLen();
			pcap_packet = expected_pkt.getRawData();

			if (shm_packet && pcap_packet_len == shm_packet->header.size &&
			    memcmp(shm_packet->memory, pcap_packet, pcap_packet_len) == 0)
			{ /// packets are the same
				continue;
			}

			/// packets are different, so...
			success = false;
			YANET_LOG_ERROR("dump [%s]: error: wrong packet #%lu (%s)\n",
			                tag.data(),
			                position,
			                expectFilePath.data());

			if (dumpPackets && shm_packet)
			{
				YANET_LOG_DEBUG("dump [%s]: expected %u, got %u\n", tag.data(), pcap_packet_len, shm_packet->header.size);
				dumper.dump(pcap_packet, pcap_packet + shm_packet->header.size, shm_packet->memory, shm_packet->memory + pcap_packet_len);
			}
		}

		/// read the remaining packets from memory ring
		for (;;)
		{
			shm_packet = read_shm_packet(ring, position);
			if (!shm_packet)
			{
				break;
			}
			position++;

			success = false;

			if (dumpPackets)
			{
				YANET_LOG_DEBUG("dump [%s]: unexpected %u\n", tag.data(), shm_packet->header.size);
				dumper.dump(nullptr, nullptr, shm_packet->memory, shm_packet->memory + pcap_packet_len);
			}
		}

		YANET_LOG_DEBUG("dump [%s]: recv %lu packets\n", tag.data(), position);

		reader->close();

		if (!success)
		{
			YANET_LOG_ERROR("dump [%s]: error: unknown packet (%s)\n", tag.data(), expectFilePath.data());
			throw "";
		}
	}

	return true;
}

void tAutotest::fflushSharedMemory()
{
	size_t size = std::get<0>(rawShmInfo);
	void* memaddr = std::get<1>(rawShmInfo);
	memset(memaddr, 0, size);
}

} // namespace autotest
