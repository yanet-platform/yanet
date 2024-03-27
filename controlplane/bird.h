/*
 *
 *    Bird packet format:
 *    +-------------+----------+---------+-----------+-----------+----------------------+----
 *    | packet_size | net_addr | new/old | remote_ip | attr_size | uint_attr/array_attr |....
 *    +-------------+----------+---------+-----------+-----------+----------------------+----
 *           4           24         4          16         4               8/var
 *
 *    Single value attribute format:
 *    +------+-------+
 *    | code | value |
 *    +------+-------+
 *       4       4
 *
 *    Array value attribute format:
 *    +------+-------+-------+
 *    | code | count | value |
 *    +------+-------+-------+
 *       4       4    4*count
 *
 */

#pragma once

#include <functional>
#include <map>
#include <mutex>
#include <set>

#include "type.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <vector>

#include <nlohmann/json.hpp>

#include "common/icp.h"

#include "controlplane.h"

namespace controlplane::module
{

#define YANET_UPDATE 0x0001 /* UPDATE or EoR */
#define YANET_ORIGIN 0x0004 /* has origin */
#define YANET_ASPATH 0x0008 /* has as-path */
#define YANET_NH 0x0010 /* has next-hop */
#define YANET_MED 0x0020 /* has multi-exit discriminator */
#define YANET_LPREF 0x0040 /* has local preference */
#define YANET_COMM 0x0080 /* has community */
#define YANET_LCOMM 0x0100 /* has large community */
#define YANET_LABELS 0x0200 /* has mpls labels */

#define IS_VPN_SAFI(s) ((s) == 0x80 || (s) == 0x81 || (s) == 0x86)

#define YANET_CONNECT_TRIES_NUMBER 10

const char* yanet_socket = "/tmp/bird-yanet.sock";

extern "C"
{
	typedef struct node
	{
		struct node *next, *prev;
	} node;

	typedef union list
	{
		struct
		{
			struct node head_node;
			void* head_padding;
		};
		struct
		{
			void* tail_padding;
			struct node tail_node;
		};
		struct
		{
			struct node* head;
			struct node* null;
			struct node* tail;
		};
	} list;

#define NODE (node*)
#define HEAD(l) ((l).head)
#define TAIL(l) ((l).tail)
#define NODE_NEXT(n) ((n)->next)
#define NODE_VALID(n) ((n)->next)
#define WALK_LIST(n, l) for (n = HEAD(l); NODE_VALID(n); n = NODE_NEXT(n))
#define EMPTY_LIST(l) (!(l).head->next)
};

struct yanet_u32
{
	uint32_t count;
	uint32_t data[0];
};

struct yanet_prefix_t
{
	node n;
	const char* prefix;
	uint32_t path_id;
};

typedef struct yanet_data
{
	uint16_t flags;
	uint16_t safi;
	uint32_t afi;
	uint32_t med;
	uint32_t lpref;
	const char* next_hop;
	std::string origin;
	std::vector<uint32_t> as_path;
	std::vector<uint32_t> community;
	std::vector<uint32_t> lcommunity;
	std::vector<uint32_t> labels;
	const char* peer;
	list prefixes;
	list withdraw;
} yanet_data_t;

struct ip6_addr
{
	uint32_t addr[4];
};

using ip_addr = ip6_addr;

struct net_addr
{
	uint8_t type;
	uint8_t pxlen;
	uint16_t length;
	uint8_t data[20];
	uint64_t align[0];
};

enum class bird_packet_type_t : int
{
	kAdd = 1,
	kDel = 2
};

struct bird_packet_head_t
{
	uint32_t length;
	net_addr net_addr;
	bird_packet_type_t type;
	ip_addr ip_addr;
};

enum class bird_packet_attr_type_t
{
	kBaOrigin = 0x01,
	kBaAsPath,
	kBaNextHop,
	kBaMultiExitDisc,
	kBaLocalPref,
	kBaAtomicAggr,
	kBaAggregator,
	kBaCommunity,
	kBaOriginatorId,
	kBaClusterList,
	kBaMpReachNlri,
	kBaMpUnreachNlri,
	kBaExtCommunity,
	kBaAs4Path,
	kBaAs4Aggregator,
	kBaLargeCommunity,
	kBaMplsLabelStack = 0xfe
};

const uint32_t BUFFER_SIZE = 1024;

class bird_t : public cModule
{
public:
	bird_t()
	{
		common::icp::rib_update::request rib_request{common::icp::rib_update::clear("bgp", std::nullopt)};
		rib_update(rib_request);
	}
	~bird_t() override
	{
		close(sock);
		unlink(yanet_socket);
	}

	eResult init() override
	{
		sock = socket(AF_UNIX, SOCK_STREAM, 0);
		if (sock < 0)
		{
			YANET_LOG_ERROR("error: could not create socket: %s\n", strerror(errno));
			return eResult::errorSocket;
		}
		int code = connect_to_socket();
		if (code != 0)
		{
			YANET_LOG_ERROR("error: could not connect to socket: %s\n", strerror(errno));
			return eResult::errorConnect;
		}
		funcThreads.emplace_back([this]() {
			bird_thread();
		});
		return eResult::success;
	}

private:
	int connect_to_socket()
	{
		remote.sun_family = AF_UNIX;
		strcpy(remote.sun_path, yanet_socket);
		int code;
		for (int i = 0; i < YANET_CONNECT_TRIES_NUMBER; ++i)
		{
			if ((code = connect(sock, (struct sockaddr*)&remote, sizeof(remote))) == 0)
			{
				break;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds{100});
		}
		return code;
	}

	void rib_update(common::icp::rib_update::request rib_request)
	{
		const common::icp::requestType type = common::icp::requestType::rib_update;
		if (!exist(controlPlane->commands, type))
		{
			YANET_LOG_ERROR("bird: rib isn't ready\n");
			throw std::runtime_error("bird can't start before rib");
		}
		common::icp::request request = {type, rib_request};
		controlPlane->commands[type](request);
	}

	void update(yanet_data_t* data)
	{
		const common::ip_address_t peer_address = std::string(data->peer); // TODO set peer
		const auto& table_name = std::string(afi2str(data->afi)) +
		                         std::string(" ") +
		                         std::string(safi2str(data->safi));
		std::string attribute_origin;
		std::string path_information;
		std::vector<uint32_t> attribute_aspath;
		std::set<common::community_t> attribute_communities;
		std::set<common::large_community_t> attribute_large_communities;
		std::vector<uint32_t> labels;
		node* n;
		yanet_prefix_t* p;
		uint32_t attribute_local_preference = 0;
		uint32_t attribute_med = 0;

		if (data->flags & YANET_ORIGIN)
			attribute_origin = std::string(data->origin);

		if (data->flags & YANET_MED)
			attribute_med = data->med;

		if (data->flags & YANET_ASPATH)
		{
			attribute_aspath = data->as_path;
		}

		if (data->flags & YANET_COMM)
		{
			for (uint32_t i = 0; i < data->community.size(); i += 2)
			{
				attribute_communities.emplace(data->community[i], data->community[i + 1]);
			}
		}

		if (data->flags & YANET_LCOMM)
		{
			for (uint32_t i = 0; i < data->community.size(); i += 3)
			{
				attribute_large_communities.emplace(data->community[i], data->community[i + 1], data->community[i + 2]);
			}
		}

		if (data->flags & YANET_LPREF)
		{
			attribute_local_preference = data->lpref;
		}

		if (data->flags & YANET_LABELS)
		{
			labels = data->labels;
		}

		{
			std::lock_guard<std::mutex> guard(rib_request_mutex);

			if (!(rib_request.size() &&
			      std::holds_alternative<common::icp::rib_update::insert>(rib_request.back())))
			{
				common::icp::rib_update::insert request = {"bgp",
				                                           "default", ///< @todo: vrf
				                                           YANET_RIB_PRIORITY_DEFAULT,
				                                           {}};

				rib_request.emplace_back(request);
			}

			auto& request_announce = std::get<3>(std::get<common::icp::rib_update::insert>(rib_request.back()))[{peer_address,
			                                                                                                     attribute_origin,
			                                                                                                     attribute_med,
			                                                                                                     attribute_aspath,
			                                                                                                     attribute_communities,
			                                                                                                     attribute_large_communities,
			                                                                                                     attribute_local_preference}];

			if (!EMPTY_LIST(data->prefixes))
			{
				auto& request_announce_table = request_announce[table_name];
				const common::ip_address_t nexthop = std::string(
				        (data->flags & YANET_NH) ? data->next_hop : data->peer);

				WALK_LIST(n, data->prefixes)
				{
					common::ip_prefix_t prefix;
					size_t pos;

					p = reinterpret_cast<yanet_prefix_t*>(n);

					if (IS_VPN_SAFI(data->safi) &&
					    (pos = std::string(p->prefix).find(' ')) != std::string::npos)
					{
						/* prefix string is prepended with RD value */
						path_information = std::string(p->prefix).substr(0, pos);
						prefix = std::string(p->prefix).substr(pos + 1);
					}
					else
						prefix = std::string(p->prefix);

					if (p->path_id != 0)
					{
						/* XXX convert it to IPv4 address representation */
						path_information = std::to_string(p->path_id);
					}

					request_announce_table[nexthop].emplace_back(prefix,
					                                             path_information,
					                                             labels);
				}
			}
		}

		if (!EMPTY_LIST(data->withdraw))
		{
			std::lock_guard<std::mutex> guard(rib_request_mutex);

			if (!(rib_request.size() &&
			      std::holds_alternative<common::icp::rib_update::remove>(rib_request.back())))
			{
				common::icp::rib_update::remove request = {"bgp",
				                                           "default", ///< @todo: vrf
				                                           YANET_RIB_PRIORITY_DEFAULT,
				                                           {}};
				rib_request.emplace_back(request);
			}

			auto& request_withdraw = std::get<3>(std::get<common::icp::rib_update::remove>(rib_request.back()))[peer_address];
			auto& request_withdraw_table = request_withdraw[table_name];

			WALK_LIST(n, data->withdraw)
			{
				common::ip_prefix_t prefix;
				size_t pos;

				p = reinterpret_cast<yanet_prefix_t*>(n);

				if (IS_VPN_SAFI(data->safi) &&
				    (pos = std::string(p->prefix).find(' ')) != std::string::npos)
				{
					/* prefix string is prepended with RD value */
					path_information = std::string(p->prefix).substr(0, pos);
					prefix = std::string(p->prefix).substr(pos + 1);
				}
				else
					prefix = std::string(p->prefix);

				if (p->path_id != 0)
				{
					path_information = std::to_string(p->path_id);
				}

				request_withdraw_table.emplace_back(prefix,
				                                    path_information,
				                                    labels);
			}
		}
		flush();
	}

	void flush()
	{
		common::icp::rib_update::request rib_request;

		{
			std::lock_guard<std::mutex> guard(rib_request_mutex);

			if (!this->rib_request.size())
			{
				return;
			}

			rib_request.swap(this->rib_request);
		}

		rib_update(rib_request);
	}

	std::string afi2str(int)
	{
		return "42"; // TODO set correct value
	}

	std::string safi2str(int)
	{
		return "42"; // TODO set correct value
	}

	inline bird_packet_head_t read_packet_head(char** cur)
	{
		bird_packet_head_t head = *(bird_packet_head_t*)cur;
		*cur += sizeof(bird_packet_head_t);
		return head;
	}

	inline uint32_t read_uint_data(char** cur)
	{
		uint32_t data = *(uint32_t*)cur;
		*cur += 4;
		return data;
	}
	inline std::vector<uint32_t> read_uint_vector(char** cur)
	{
		uint32_t count = read_uint_data(cur);
		std::vector<uint32_t> data;
		data.reserve(count);
		for (uint32_t i = 0; i < count; ++i)
		{
			data.emplace_back(read_uint_data(cur));
		}
		return data;
	}

	inline std::string process_ba_origin(char** cur)
	{
		static const char* bgp_origins[] = {"igp", "egp", "incomplete"};
		uint32_t data = read_uint_data(cur);
		std::string origin = (data <= 2) ? bgp_origins[data] : bgp_origins[2];
		return origin;
	}

	yanet_data_t parse_attrs(char* cur)
	{
		yanet_data_t data;
		char* attr_start = cur;
		uint32_t attr_len = read_uint_data(&cur);

		for (; cur != attr_start + attr_len;)
		{
			bird_packet_attr_type_t code = (bird_packet_attr_type_t)read_uint_data(&cur);
			switch (code)
			{
				case bird_packet_attr_type_t::kBaOrigin:
				{
					data.flags |= YANET_ORIGIN;
					data.origin = process_ba_origin(&cur);
					break;
				}
				case bird_packet_attr_type_t::kBaLocalPref:
				{
					data.flags |= YANET_LPREF;
					data.lpref = read_uint_data(&cur);
					break;
				}
				case bird_packet_attr_type_t::kBaMultiExitDisc:
				{
					data.flags |= YANET_MED;
					data.med = read_uint_data(&cur);
					break;
				}
				case bird_packet_attr_type_t::kBaOriginatorId:
					// TODO
					break;
				case bird_packet_attr_type_t::kBaAsPath:
				{
					data.flags |= YANET_ASPATH;
					data.as_path = read_uint_vector(&cur);
					break;
				}
				case bird_packet_attr_type_t::kBaNextHop:
					// TODO
					break;
				case bird_packet_attr_type_t::kBaCommunity:
				{
					data.flags |= YANET_COMM;
					data.community = read_uint_vector(&cur);
					break;
				}
				case bird_packet_attr_type_t::kBaExtCommunity:
					// TODO
					break;
				case bird_packet_attr_type_t::kBaLargeCommunity:
				{
					data.flags |= YANET_LCOMM;
					data.lcommunity = read_uint_vector(&cur);
					break;
				}
				case bird_packet_attr_type_t::kBaMplsLabelStack:
				{
					data.flags |= YANET_LABELS;
					data.labels = read_uint_vector(&cur);
					break;
				}
				case bird_packet_attr_type_t::kBaClusterList:
					// TODO
					break;
				case bird_packet_attr_type_t::kBaAtomicAggr:
				case bird_packet_attr_type_t::kBaAggregator:
				case bird_packet_attr_type_t::kBaMpReachNlri:
				case bird_packet_attr_type_t::kBaMpUnreachNlri:
				case bird_packet_attr_type_t::kBaAs4Path:
				case bird_packet_attr_type_t::kBaAs4Aggregator:
					YANET_LOG_WARNING("Unsupported bird attribute %d", (int)bird_packet_attr_type_t::kBaAtomicAggr);
					break;
			}
		}
		return data;
	}

	void bird_thread()
	{
		char buffer[BUFFER_SIZE]; // TODO use bigger BUFFER_SIZE or read smarter
		for (;;)
		{
			bird_packet_head_t header;
			int len = read(sock, (char*)&header, sizeof(header));
			if (len < 0)
			{
				// TODO connect again if failed
			}
			else if (len == 0)
			{
				std::this_thread::sleep_for(std::chrono::milliseconds{100});
			}
			else
			{
				// Read the rest of the data
				len = read(sock, buffer, header.length - sizeof(header));
				char* cur = buffer;
				yanet_data_t yanet_data = parse_attrs(cur);
				switch (header.type)
				{
					case bird_packet_type_t::kAdd:
					{
						update(&yanet_data);
						break;
					}
					case bird_packet_type_t::kDel:
					{
						// TODO
						break;
					}
				}
			}
		}
	}

protected:
	int sock;
	sockaddr_un remote;
	std::mutex rib_request_mutex;
	common::icp::rib_update::request rib_request;
	std::map<common::ip_address_t, common::uint8> peers_state;
};

}
