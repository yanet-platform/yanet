#include "libbird.h"

#include "common/icp.h"
#include "common/type.h"
#include "controlplane/rib.h"
#include <sys/un.h>
#include <unistd.h>
#include <vector>

static inline bool
decode_u8(uintptr_t* ppos, uintptr_t end, uint8_t* pvalue)
{
	if (*ppos + sizeof(uint8_t) > end)
		return false;
	*pvalue = *(uint8_t*)*ppos;
	*ppos += sizeof(uint8_t);
	return true;
}

static inline bool
decode_u16(uintptr_t* ppos, uintptr_t end, uint16_t* pvalue)
{
	if (*ppos + sizeof(uint16_t) > end)
		return false;
	*pvalue = *(uint16_t*)*ppos;
	*ppos += sizeof(uint16_t);
	return true;
}

static inline bool
decode_u32(uintptr_t* ppos, uintptr_t end, uint32_t* pvalue)
{
	if (*ppos + sizeof(uint32_t) > end)
		return false;
	*pvalue = *(uint32_t*)*ppos;
	*ppos += sizeof(uint32_t);
	return true;
}

static inline bool
decode_chunk(uintptr_t* ppos, uintptr_t end, uintptr_t* pchunk_end)
{
	uint32_t chunk_size;
	if (!decode_u32(ppos, end, &chunk_size))
		return false;
	*pchunk_end = *ppos + chunk_size;
	return *pchunk_end <= end;
}

static inline bool
decode_u32_array(uintptr_t* ppos, uintptr_t end, uintptr_t* parray_end)
{
	uint32_t array_count;
	if (!decode_u32(ppos, end, &array_count))
		return false;
	*parray_end = *ppos + sizeof(uint32_t) * array_count;
	return (*parray_end <= end);
}

static inline bool
decode_ip_addr(uintptr_t* ppos, uintptr_t end, ip_addr* paddr)
{
	if (*ppos + sizeof(ip_addr) > end)
		return false;
	*paddr = *(ip_addr*)*ppos;
	*ppos += sizeof(ip_addr);
	return true;
}

static inline bool
decode_net_addr(uintptr_t* ppos, uintptr_t end, net_addr_union* paddr)
{
	if (*ppos + sizeof(net_addr_union) > end)
		return false;
	*paddr = *(net_addr_union*)*ppos;
	// Some members of net_addr_union are variable length structures so
	// check the length attribute.
	if (*ppos + paddr->n.length > end)
		return false;
	if (paddr->n.length <= sizeof(net_addr_union))
	{
		*ppos += sizeof(net_addr_union);
		return true;
	}
	return false;
	/*
	 * FIXME: this is not supported yet
	memcpy(
	        paddr + 1, (void *)(*ppos + sizeof(net_addr_union)),
	        paddr->n.length - sizeof(net_addr_union)
	);
	*ppos += paddr->n.length;
	return true;
	*/
}

static inline bool
decode_u16_array(uintptr_t* ppos, uintptr_t end, std::vector<uint16_t>* values)
{
	size_t attr_end;
	if (!decode_chunk(ppos, end, &attr_end))
	{
		return false;
	}

	while (*ppos < attr_end)
	{
		uint16_t value;
		if (!decode_u16(ppos, attr_end, &value))
		{
			return false;
		}

		values->emplace_back(value);
	}

	return true;
}

static inline bool
decode_u32_array(uintptr_t* ppos, uintptr_t end, std::vector<uint32_t>* values)
{
	size_t attr_end;
	if (!decode_chunk(ppos, end, &attr_end))
	{
		return false;
	}

	while (*ppos < attr_end)
	{
		uint32_t value;
		if (!decode_u32(ppos, attr_end, &value))
		{
			return false;
		}

		values->emplace_back(value);
	}

	return true;
}

static inline bool
decode_as_path(uintptr_t* ppos, uintptr_t end, std::vector<uint32_t>* as_path)
{
	size_t attr_end;
	if (!decode_chunk(ppos, end, &attr_end))
	{
		return false;
	}

	while (*ppos < attr_end)
	{
		uint8_t segment_type;
		if (!decode_u8(ppos, attr_end, &segment_type))
		{
			return false;
		}

		if (segment_type != 2 && segment_type != 3)
		{
			return false;
		}

		uint8_t segment_len;
		if (!decode_u8(ppos, attr_end, &segment_len))
		{
			return false;
		}

		for (uint16_t idx = 0; idx < segment_len; ++idx)
		{
			uint32_t as;
			if (!decode_u32(ppos, attr_end, &as))
			{
				return false;
			}
			as = ntohl(as);
			as_path->emplace_back(as);
		}
	}

	return true;
}

static inline bool
ipa_is_ip4(ip_addr addr)
{
	return addr.addr[0] == 0 && addr.addr[1] == 0 && addr.addr[2] == 0xffff;
}

static inline common::ipv4_address_t
ipa_to_address_4(ip_addr addr)
{
	return common::ipv4_address_t(addr.addr[3]);
}

static inline common::ipv6_address_t
ipa_to_address_6(ip_addr addr)
{
	addr.addr[0] = ntohl(addr.addr[0]);
	addr.addr[1] = ntohl(addr.addr[1]);
	addr.addr[2] = ntohl(addr.addr[2]);
	addr.addr[3] = ntohl(addr.addr[3]);
	return common::ipv6_address_t((uint8_t*)&addr);
}

static inline common::ip_address_t
ipa_to_address(ip_addr addr)
{
	if (ipa_is_ip4(addr))
		return common::ip_address_t(ipa_to_address_4(addr));
	return common::ip_address_t(ipa_to_address_6(addr));
}

static inline bool
recover_prefix_info(net_addr_union* paddr, common::ip_prefix_t* prefix, common::ip_address_t* vpnDST, uint32_t* vpnRD)
{

	switch (paddr->n.type)
	{
		case NET_IP4:
		{
			*prefix = common::ip_prefix_t(common::ipv4_address_t(paddr->ip4.prefix), paddr->ip4.pxlen);
			break;
		}

		case NET_IP6:
		{
			*prefix = common::ip_prefix_t(ipa_to_address_6(paddr->ip6.prefix), paddr->ip6.pxlen);
			break;
		}

		case NET_VPN4:
		{
			if ((paddr->vpn4.rd >> 48) != 1)
			{
				return false;
			}

			*prefix = common::ip_prefix_t(common::ipv4_address_t(paddr->vpn4.prefix), paddr->vpn4.pxlen);
			*vpnDST = common::ip_address_t(common::ipv4_address_t(paddr->vpn4.rd >> 16));
			*vpnRD = paddr->vpn4.rd & 0xffff;
			break;
		}

		case NET_VPN6:
		{
			if ((paddr->vpn6.rd >> 48) != 1)
			{
				return false;
			}

			*prefix = common::ip_prefix_t(ipa_to_address_6(paddr->vpn6.prefix), paddr->vpn6.pxlen);
			*vpnDST = common::ip_address_t(common::ipv4_address_t(paddr->vpn4.rd >> 16));
			*vpnRD = paddr->vpn6.rd & 0xffff;

			break;
		}

		default:
			return false;
	}

	return true;
}

static inline bool
recover_next_hop(uintptr_t* ppos, uintptr_t end, common::ip_address_t* next_hop)
{
	if (end - *ppos != sizeof(ip_addr) &&
	    end - *ppos != 2 * sizeof(ip_addr))
	{
		return false;
	}

	if (end - *ppos == sizeof(ip_addr))
	{
		ip_addr nh_addr;
		if (!decode_ip_addr(ppos, end, &nh_addr))
		{
			return false;
		}
		*next_hop = ipa_to_address(nh_addr);
		return true;
	}

	ip_addr nh_addr1;
	ip_addr nh_addr2;
	if (!decode_ip_addr(ppos, end, &nh_addr1) ||
	    !decode_ip_addr(ppos, end, &nh_addr2))
	{
		return false;
	}

	if (nh_addr2.addr[0] == 0 && nh_addr2.addr[1] == 0 &&
	    nh_addr2.addr[2] == 0 && nh_addr2.addr[3] == 0)
	{
		*next_hop = ipa_to_address(nh_addr1);
	}
	else
	{
		*next_hop = ipa_to_address(nh_addr2);
	}

	return true;
}

static bool
parse_route_update(uintptr_t* ppos, uintptr_t end, const char* vrf, common::icp::rib_update::action* paction)
{
	common::ip_address_t peer_address;
	std::string attribute_origin;
	std::string path_information;
	std::vector<uint32_t> attribute_aspath;
	std::set<common::community_t> attribute_communities;
	std::set<common::large_community_t> attribute_large_communities;
	std::vector<uint32_t> labels;

	uint32_t attribute_local_preference = 0;
	uint32_t attribute_med = 0;

	common::ip_address_t next_hop;
	common::ip_prefix_t prefix;
	common::ip_address_t vpnDST;
	uint32_t vpnRD = 0;

	/* Decode route prefix. */
	net_addr_union addr;
	if (!decode_net_addr(ppos, end, &addr))
		return false;

	if (!recover_prefix_info(&addr, &prefix, &vpnDST, &vpnRD))
		return false;

	uint32_t type;
	if (!decode_u32(ppos, end, &type))
		return false;

	ip_addr remote_addr;
	if (!decode_ip_addr(ppos, end, &remote_addr))
		return false;
	peer_address = ipa_to_address(remote_addr);

	size_t attrs_end;
	if (!decode_chunk(ppos, end, &attrs_end))
		return false;

	if (attrs_end != end)
		return false;

	/* Now decode all attributes one by one. */
	while (*ppos < attrs_end)
	{
		uint32_t attr_id;
		if (!decode_u32(ppos, attrs_end, &attr_id))
			return false;

		switch (EA_ID(attr_id))
		{
			case BA_ORIGIN:
			{
				uint32_t origin;
				if (!decode_u32(ppos, attrs_end, &origin))
				{
					return false;
				}
				switch (origin)
				{
					case 0:
						attribute_origin = "IGP";
						break;
					case 1:
						attribute_origin = "EGP";
						break;
					case 2:
						attribute_origin = "Incomplete";
						break;
					default:
						attribute_origin = "?";
				}

				break;
			}

			case BA_MULTI_EXIT_DISC:
			{
				uint32_t med;
				if (!decode_u32(ppos, attrs_end, &med))
				{
					return false;
				}

				attribute_med = med;

				break;
			}

			case BA_LOCAL_PREF:
			{
				uint32_t pref;
				if (!decode_u32(ppos, attrs_end, &pref))
				{
					return false;
				}

				attribute_local_preference = pref;

				break;
			}

			case BA_ORIGINATOR_ID:
			{
				uint32_t originator;
				if (!decode_u32(ppos, attrs_end, &originator))
				{
					return false;
				}

				break;
			}

			case BA_AS_PATH:
			{
				if (!decode_as_path(ppos, attrs_end, &attribute_aspath))
				{
					return false;
				}

				break;
			}

			case BA_NEXT_HOP:
			{
				size_t attr_end;
				if (!decode_chunk(ppos, attrs_end, &attr_end))
				{
					return false;
				}

				if (!recover_next_hop(ppos, attr_end, &next_hop))
				{
					return false;
				}

				break;
			}

			case BA_COMMUNITY:
			{
				std::vector<uint16_t> communities;
				if (!decode_u16_array(ppos, attrs_end, &communities))
				{
					return false;
				}

				if (communities.size() % 2 != 0)
				{
					return false;
				}

				for (size_t idx = 0; idx < communities.size() / 2; ++idx)
				{
					attribute_communities.emplace(
					        communities[idx * 2 + 0],
					        communities[idx * 2 + 1]);
				}

				break;
			}

			case BA_CLUSTER_LIST:
			{
				std::vector<uint32_t> clusters;
				if (!decode_u32_array(ppos, attrs_end, &clusters))
				{
					return false;
				}

				break;
			}

			case BA_EXT_COMMUNITY:
			{
				std::vector<uint32_t> ext_communities;
				if (!decode_u32_array(ppos, attrs_end, &ext_communities))
				{
					return false;
				}

				break;
			}

			case BA_LARGE_COMMUNITY:
			{
				std::vector<uint32_t> large_communities;
				if (!decode_u32_array(ppos, attrs_end, &large_communities))
				{
					return false;
				}

				if (large_communities.size() % 3 != 0)
				{
					return false;
				}

				for (size_t idx = 0; idx < large_communities.size() / 3;
				     ++idx)
				{

					attribute_large_communities.emplace(
					        large_communities[idx * 3 + 0],
					        large_communities[idx * 3 + 1],
					        large_communities[idx * 3 + 2]);
				}

				break;
			}

			case BA_MPLS_LABEL_STACK:
			{
				if (!decode_u32_array(ppos, attrs_end, &labels))
				{
					return false;
				}

				break;
			}

			default:
				return false;
		}
	}

	std::string afi;
	std::string safi;

	// FIXME: table name
	if (prefix.is_ipv4())
	{
		afi = "ipv4";
	}
	else
	{
		afi = "ipv6";
	}

	if (vpnRD == 0)
	{
		safi = "unicast";
	}
	else
	{
		safi = "mpls-vpn";
	}

	if (type == 1)
	{
		common::icp::rib_update::insert insert = {"bgp",
		                                          std::string(vrf),
		                                          YANET_RIB_PRIORITY_DEFAULT,
		                                          {}};

		auto& announce = std::get<3>(insert)[{peer_address,
		                                      attribute_origin,
		                                      attribute_med,
		                                      attribute_aspath,
		                                      attribute_communities,
		                                      attribute_large_communities,
		                                      attribute_local_preference}];

		auto& announce_table = announce[afi + " " + safi];
		announce_table[next_hop].emplace_back(prefix, std::to_string(vpnRD), labels);

		*paction = insert;
	}
	else
	{
		common::icp::rib_update::remove remove = {"bgp",
		                                          std::string(vrf),
		                                          YANET_RIB_PRIORITY_DEFAULT,
		                                          {}};

		auto& announce = std::get<3>(remove)[peer_address];

		// FIXME: table name
		auto& announce_table = announce[afi + " " + safi];
		announce_table.emplace_back(prefix, std::to_string(vpnRD), labels);

		*paction = remove;
	}

	return true;
}

/**
 * read_bird_feed
 * @sock_name: the path to the unix socket through which bird uploads data
 * @vrf: the string with the vrf name
 * @handler: handler events for receiving data from bird
 * @pipe_close: the pipe descriptor through which information about the need to terminate the stream will
 *              be transmitted, a negative value means that verification should be disabled.
 *
 * return value:
 * - true: some kind of error has occurred and it may be worth running the function after some time interval.
 * - false: data was received through pipe indicating that the thread needs to be completed
 */
bool read_bird_feed(const char* sock_name, const char* vrf, rib_update_handler handler, int pipe_close)
{
	bool result = true;
	/* Connect to bird export socket. */
	int bird_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un server_addr;
	server_addr.sun_family = AF_UNIX;
	strncpy(server_addr.sun_path, sock_name, sizeof(server_addr.sun_path) - 1);
	if (connect(bird_sock,
	            (struct sockaddr*)&server_addr,
	            sizeof(server_addr)) != 0)
	{
		YANET_LOG_ERROR("error connect to socket %s, %d: %s\n", server_addr.sun_path, errno, strerror(errno));
		return result;
	}

	/*
	 * Read buffer is used to accumulate multuple route updates and
	 * flush then at once. 1Mib looks good as the buffur size.
	 */
	const size_t buf_size = 1 << 20;
	void* read_buf = malloc(buf_size);
	if (read_buf == NULL)
	{
		YANET_LOG_ERROR("error malloc buffer size: %ld", buf_size);
		if (pipe_close >= 0)
		{
			close(pipe_close);
		}
		close(bird_sock);
		return result;
	}
	/*
	 * The variable is the offset to read data to and denotes the first
	 * byte which could nit be parsed yet.
	 */
	size_t read_pos = 0;
	/*
	 * Parse position is the position of the next one route update to
	 * process.
	 */
	size_t parse_pos = 0;

	common::icp::rib_update::request requests;

	for (;;)
	{
		if (pipe_close >= 0)
		{
			/* Waiting either for receiving data in the socket, or for a signal to close the stream via pipe */
			int max_sd = (pipe_close > bird_sock ? pipe_close : bird_sock);
			fd_set rfds;
			FD_ZERO(&rfds);
			FD_SET(pipe_close, &rfds);
			FD_SET(bird_sock, &rfds);

			int retval = select(max_sd + 1, &rfds, NULL, NULL, NULL);
			if (retval < 0)
			{
				YANET_LOG_ERROR("!!!!! error select %d: %s\n", errno, strerror(errno));
			}
			else if (FD_ISSET(pipe_close, &rfds))
			{
				result = false;
				YANET_LOG_INFO("closing thread for reading the vrf=%s from the bird socket: %s\n", vrf, sock_name);
				break;
			}
		}

		/* Read as mush as possible data */
		ssize_t readen = read(bird_sock,
		                      (void*)((uintptr_t)read_buf + read_pos),
		                      buf_size - read_pos);
		if (readen <= 0)
		{
			break;
		}

		/* Adust read postion and try to recover next route update. */
		read_pos += readen;
		while (parse_pos < read_pos)
		{
			/* pos and end denote addresses of a memory chunk to parse. */
			uintptr_t pos = (uintptr_t)read_buf + parse_pos;
			uintptr_t end = (uintptr_t)read_buf + read_pos;

			/* Determine boundaries of the next route update. */
			uintptr_t route_end;
			if (!decode_chunk(&pos, end, &route_end))
				break;

			common::icp::rib_update::action action;
			if (!parse_route_update(&pos, route_end, vrf, &action))
				break;

			requests.emplace_back(action);

			parse_pos = pos - (uintptr_t)read_buf;
		}

		handler(requests);
		requests.clear();

		if (buf_size - read_pos < buf_size / 2)
		{
			memmove(read_buf,
			        (void*)((uintptr_t)read_buf + parse_pos),
			        read_pos - parse_pos);
			read_pos = read_pos - parse_pos;
			parse_pos = 0;
		}
	}

	if (pipe_close >= 0)
	{
		close(pipe_close);
	}
	free(read_buf);
	close(bird_sock);

	return result;
}
