#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "common/define.h"
#include "common/icontrolplane.h"
#include "common/result.h"
#include "common/type.h"

#include "libyabird.h"

#define YANET_LOG_PATH "/var/log/yanet-bird.log"

common::log::LogPriority common::log::logPriority = common::log::TLOG_DEBUG;

struct libyabird_t
{
public:
	libyabird_t();
	~libyabird_t();

	void set_state(const char* peer, int state);
	void update(yanet_data_t* data);

protected:
	void worker_proc();
	void flush();

protected:
	std::ofstream log;
	interface::controlPlane controlPlane;

	std::vector<std::thread> threads;

	std::mutex rib_request_mutex;
	common::icp::rib_update::request rib_request;

	std::map<common::ip_address_t, common::uint8> peers_state;
};

libyabird_t::libyabird_t()
{
	log.open(YANET_LOG_PATH, std::ios_base::app);

	if (!log.is_open())
	{
		/* XXX */
		throw std::string("error: open('" YANET_LOG_PATH "')");
	}

	std::time_t current_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
	log << std::ctime(&current_time) << "libyabird instance started" << std::endl;

	/* connect to controlplane */
	controlPlane.rib_update({common::icp::rib_update::clear("bgp", std::nullopt)});

	threads.emplace_back([this] { worker_proc(); });
}

libyabird_t::~libyabird_t()
{
	std::time_t current_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

	log << std::ctime(&current_time) << "libyabird instance stopped" << std::endl;
	log.close();
}

void libyabird_t::set_state(const char* peer, int state)
{
	const common::ip_address_t peer_address = std::string(peer);
	std::time_t current_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

	log << std::ctime(&current_time);
	log << "peer: " << peer_address.toString().data() << ", state: " << state << std::endl;
	log << std::endl;

	auto state_prev = peers_state[peer_address];
	auto& state_next = peers_state[peer_address];

	if (state != 0)
	{
		state_next = 1;
	}
	else
	{
		state_next = 0;
	}

	if (state_prev == 1 && state_next == 0)
	{
		common::icp::rib_update::clear request = {"bgp", std::nullopt};

		std::get<1>(request) = {peer_address,
		                        {"default", ///< @todo: vrf
		                         YANET_RIB_PRIORITY_DEFAULT}};

		{
			std::lock_guard<std::mutex> guard(rib_request_mutex);
			rib_request.emplace_back(request);
		}
	}
}

static const char*
afi2str(uint32_t afi)
{
	switch (afi)
	{
		case 0x01:
			return ("ipv4");
		case 0x02:
			return ("ipv6");
		case 0x19:
			return ("l2vpn");
		case 0x4004:
			return ("bgp-ls");
	}
	return ("unknown");
}

#define IS_VPN_SAFI(s) ((s) == 0x80 || (s) == 0x81 || (s) == 0x86)

static const char*
safi2str(uint16_t safi)
{
	switch (safi)
	{
		case 0x01:
			return ("unicast");
		case 0x02:
			return ("multicast");
		case 0x04:
			return ("nlri-mpls");
		case 0x80:
			return ("mpls-vpn");
		case 0x81:
			return ("multicast-vpn");
		case 0x85:
			return ("flow");
		case 0x86:
			return ("flow-vpn");
	}
	return ("unknown");
}

void libyabird_t::update(yanet_data_t* data)
{
	const common::ip_address_t peer_address = std::string(data->peer);
	const auto& table_name = std::string(afi2str(data->afi)) +
	                         std::string(" ") +
	                         std::string(safi2str(data->safi));

	if ((data->flags & YANET_UPDATE) == 0)
	{
		std::time_t current_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
		log << std::ctime(&current_time);
		log << "eor: " << peer_address.toString() << ", " << table_name << std::endl;
		log << std::endl;

		std::lock_guard<std::mutex> guard(rib_request_mutex);

		{
			common::icp::rib_update::eor request = {"bgp",
			                                        "default",
			                                        YANET_RIB_PRIORITY_DEFAULT,
			                                        peer_address,
			                                        table_name};

			rib_request.emplace_back(request);
		}
	}
	else
	{
		std::string attribute_origin;
		std::string path_information;
		std::vector<uint32_t> attribute_aspath;
		std::set<common::community_t> attribute_communities;
		std::set<common::large_community_t> attribute_large_communities;
		std::vector<uint32_t> labels;
		node* n;
		yanet_prefix_t* p;
		yanet_u32_t* uptr;
		uint32_t attribute_local_preference = 0;
		uint32_t attribute_med = 0;
		uint32_t i;

		if (data->flags & YANET_ORIGIN)
			attribute_origin = std::string(data->origin);

		if (data->flags & YANET_MED)
			attribute_med = data->med;

		if (data->flags & YANET_ASPATH)
		{
			for (i = 0, uptr = data->as_path; i < uptr->count; i++)
			{
				attribute_aspath.emplace_back(uptr->data[i]);
			}
		}

		if (data->flags & YANET_COMM)
		{
			for (i = 0, uptr = data->community; i < uptr->count; i += 2)
			{
				attribute_communities.emplace(uptr->data[i], uptr->data[i + 1]);
			}
		}

		if (data->flags & YANET_LCOMM)
		{
			for (i = 0, uptr = data->lcommunity; i < uptr->count; i += 3)
			{
				attribute_large_communities.emplace(uptr->data[i], uptr->data[i + 1], uptr->data[i + 2]);
			}
		}

		if (data->flags & YANET_LPREF)
			attribute_local_preference = data->lpref;

		if (data->flags & YANET_LABELS)
		{
			for (i = 0, uptr = data->labels; i < uptr->count; i++)
			{
				labels.emplace_back(uptr->data[i]);
			}
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
	}
}

void libyabird_t::flush()
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

	controlPlane.rib_update(rib_request);
}

void libyabird_t::worker_proc()
{
	for (;;)
	{
		flush();
		std::this_thread::sleep_for(std::chrono::milliseconds{100});
	}
}

extern "C" struct libyabird_t*
yanet_open(void)
{
	try
	{
		return new libyabird_t;
	}
	catch (const std::string& error)
	{
		std::cerr << __func__ << " failed: " << error.data() << std::endl;
	}
	catch (...)
	{
		std::cerr << __func__ << " failed" << std::endl;
	}
	return (NULL);
}

extern "C" void
yanet_close(struct libyabird_t* lh)
{
	delete lh;
}

extern "C" void
yanet_update(struct libyabird_t* lh, yanet_data_t* data)
{
	try
	{
		lh->update(data);
	}
	catch (const std::string& error)
	{
		std::cerr << __func__ << " failed: " << error.data() << std::endl;
	}
	catch (...)
	{
		std::cerr << __func__ << " failed" << std::endl;
	}
}

extern "C" void
yanet_set_state(struct libyabird_t* lh, const char* peer, int state)
{
	try
	{
		lh->set_state(peer, state);
	}
	catch (const std::string& error)
	{
		std::cerr << __func__ << " failed: " << error.data() << std::endl;
	}
	catch (...)
	{
		std::cerr << __func__ << " failed" << std::endl;
	}
}
