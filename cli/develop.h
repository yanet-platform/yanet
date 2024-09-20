#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <sys/shm.h>
#include <thread>
#include <vector>

#include "common/icontrolplane.h"
#include "common/idataplane.h"
#include "common/sdpclient.h"
#include "common/tsc_deltas.h"

#include "helper.h"

namespace develop
{

namespace dataplane
{

static inline void printValue(const common::idp::value& value)
{
	const auto& type = std::get<0>(value);
	if (type == common::globalBase::eNexthopType::drop)
	{
		printf("  drop\n");
	}
	else if (type == common::globalBase::eNexthopType::interface)
	{
		for (const auto& iter : std::get<1>(value))
		{
			if (std::get<0>(std::get<1>(iter)) != common::unlabelled)
			{
				if (std::get<0>(std::get<2>(iter)) != common::unlabelled)
				{
					printf("  interfaceId: %u,\ttransport: [label: %u, exp: %u],\tservice: [label: %u, exp: %u]\n",
					       std::get<0>(iter),
					       std::get<0>(std::get<1>(iter)),
					       std::get<1>(std::get<1>(iter)),
					       std::get<0>(std::get<2>(iter)),
					       std::get<1>(std::get<2>(iter)));
				}
				else
				{
					printf("  interfaceId: %u,\ttransport: [label: %u, exp: %u]\n",
					       std::get<0>(iter),
					       std::get<0>(std::get<1>(iter)),
					       std::get<1>(std::get<1>(iter)));
				}
			}
			else
			{
				printf("  interfaceId: %u\n",
				       std::get<0>(iter));
			}
		}
	}
	else if (type == common::globalBase::eNexthopType::controlPlane)
	{
		printf("  controlPlane\n");
	}
	else
	{
		printf("  error\n");
	}
}

void lpm4LookupAddress(const common::ipv4_address_t& address)
{
	interface::dataPlane dataPlane;
	const auto response = dataPlane.lpm4LookupAddress(address);
	for (const auto& iter : response)
	{
		const auto& socketId = iter.first;
		const auto& found = std::get<0>(iter.second);
		const auto& valueId = std::get<1>(iter.second);
		const auto& value = std::get<2>(iter.second);

		printf("[socketId: %u] %s -> ", socketId, common::ipv4_address_t(address).toString().data());
		if (found)
		{
			printf("valueId: %u\n", valueId);
			printValue(value);
		}
		else
		{
			printf("not found\n");
		}
	}
}

void lpm6LookupAddress(const common::ipv6_address_t& ipv6Address)
{
	interface::dataPlane dataPlane;
	const auto response = dataPlane.lpm6LookupAddress(ipv6Address);
	for (const auto& iter : response)
	{
		const auto& socketId = iter.first;
		const auto& found = std::get<0>(iter.second);
		const auto& valueId = std::get<1>(iter.second);
		const auto& value = std::get<2>(iter.second);

		printf("[socketId: %u] %s -> ", socketId, common::ipv6_address_t(ipv6Address).toString().data());
		if (found)
		{
			printf("valueId: %u\n", valueId);
			printValue(value);
		}
		else
		{
			printf("not found\n");
		}
	}
}

void getErrors()
{
	interface::dataPlane dataPlane;
	const auto response = dataPlane.getErrors();

	printf("errors:\n");
	for (const auto& iter : response)
	{
		printf("  (%lu) %s\n",
		       iter.second.value,
		       iter.first.data());
	}
}

void getReport()
{
	interface::dataPlane dataPlane;
	const auto response = dataPlane.getReport();
	printf("%s\n", response.data());
}

void counter(const uint32_t& counter_id,
             const std::optional<uint32_t>& range_size)
{
	interface::dataPlane dataplane;

	std::vector<tCounterId> counter_ids = {counter_id};
	if (range_size && (*range_size) > 0)
	{
		for (uint32_t offset = 0;
		     offset < (*range_size) - 1;
		     offset++)
		{
			counter_ids.emplace_back(counter_id + offset + 1);
		}
	}

	const auto response = common::sdp::SdpClient::GetCounters(counter_ids);

	table_t table;
	table.insert("counter_id",
	             "value");

	for (uint32_t i = 0;
	     i < counter_ids.size();
	     i++)
	{
		table.insert(counter_ids[i],
		             response[i]);
	}

	table.print();
}

using namespace ::dataplane::perf;
class tsc_monitoring_t
{
public:
	void connect_shm()
	{
		interface::dataPlane dataplane;
		const auto response = dataplane.get_shm_tsc_info();
		std::map<key_t, void*> ipc_cache;

		for (const auto& [core, socket, ipc_key, offset] : response)
		{
			(void)socket;
			if (ipc_cache.find(ipc_key) == ipc_cache.end())
			{
				auto shmid = shmget(ipc_key, 0, 0);
				if (shmid == -1)
				{
					throw std::string("shmget(") + std::to_string(ipc_key) + ", 0, 0) = " + std::strerror(errno);
				}
				auto shmaddr = shmat(shmid, nullptr, SHM_RDONLY);
				if (shmaddr == (void*)-1)
				{
					throw std::string("shmat(") + std::to_string(ipc_key) + ", nullptr, 0) = " + std::strerror(errno);
				}

				ipc_cache[ipc_key] = shmaddr;
			}

			auto counter_addr = (tsc_deltas*)((intptr_t)ipc_cache[ipc_key] + offset);
			worker_counters.emplace_back(core, counter_addr, tsc_deltas{}, overflow_store{});
		}
	}

	void monitor()
	{
		connect_shm();
		for (auto iter = 0;; iter++)
		{
			if (iter % 4 == 0)
			{
				insert_header();
			}

			for (auto& [core_id, counter, previous_value, overflow_store] : worker_counters)
			{
				const auto& counter_copy = *counter;
				for (auto bin = 0; bin < YANET_TSC_BINS_N; bin++)
				{
					overflow_store.handle_overflow(counter_copy, previous_value, bin);
					if (iter % 4 == 0)
					{
						insert_bin(counter_copy, overflow_store, bin, core_id);
					}
				}

				previous_value = counter_copy;
			}

			if (iter % 4 == 0)
			{
				table.render();
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(250));
		}
	}

protected:
	struct overflow_store;

	void insert_header()
	{
		table.insert("core_id",
		             "iter_num",
		             "logicalPort_ingress",
		             "acl_ingress4",
		             "acl_ingress6",
		             "tun64_ipv4",
		             "tun64_ipv6",
		             "route4",
		             "route6",
		             "decap",
		             "nat64stateful_lan",
		             "nat64stateful_wan",
		             "nat64stateless_egress",
		             "nat64stateless_ingress",
		             "nat46clat_lan",
		             "nat46clat_wan",
		             "balancer",
		             "balancer_icmp_reply",
		             "balancer_icmp_forward",
		             "route_tunnel4",
		             "route_tunnel6",
		             "acl_egress4",
		             "acl_egress6",
		             "logicalPort_egress",
		             "controlPlane");
	}

	void insert_bin(const tsc_deltas& cnt, const overflow_store& of_store, int bin, uint32_t core_id)
	{
		table.insert(bin == 0 ? std::to_string(core_id) : std::string{},
		             bin == 0 ? std::to_string(cnt.iter_num) : std::string{},
		             of_store.logicalPort_ingress_handle[bin] + cnt.logicalPort_ingress_handle[bin],
		             of_store.acl_ingress_handle4[bin] + cnt.acl_ingress_handle4[bin],
		             of_store.acl_ingress_handle6[bin] + cnt.acl_ingress_handle6[bin],
		             of_store.tun64_ipv4_handle[bin] + cnt.tun64_ipv4_handle[bin],
		             of_store.tun64_ipv6_handle[bin] + cnt.tun64_ipv6_handle[bin],
		             of_store.route_handle4[bin] + cnt.route_handle4[bin],
		             of_store.route_handle6[bin] + cnt.route_handle6[bin],

		             of_store.decap_handle[bin] + cnt.decap_handle[bin],
		             of_store.nat64stateful_lan_handle[bin] + cnt.nat64stateful_lan_handle[bin],
		             of_store.nat64stateful_wan_handle[bin] + cnt.nat64stateful_wan_handle[bin],
		             of_store.nat64stateless_egress_handle[bin] + cnt.nat64stateless_egress_handle[bin],
		             of_store.nat64stateless_ingress_handle[bin] + cnt.nat64stateless_ingress_handle[bin],
		             of_store.nat46clat_lan_handle[bin] + cnt.nat46clat_lan_handle[bin],
		             of_store.nat46clat_wan_handle[bin] + cnt.nat46clat_wan_handle[bin],
		             of_store.balancer_handle[bin] + cnt.balancer_handle[bin],

		             of_store.balancer_icmp_reply_handle[bin] + cnt.balancer_icmp_reply_handle[bin],
		             of_store.balancer_icmp_forward_handle[bin] + cnt.balancer_icmp_forward_handle[bin],
		             of_store.route_tunnel_handle4[bin] + cnt.route_tunnel_handle4[bin],
		             of_store.route_tunnel_handle6[bin] + cnt.route_tunnel_handle6[bin],
		             of_store.acl_egress_handle4[bin] + cnt.acl_egress_handle4[bin],
		             of_store.acl_egress_handle6[bin] + cnt.acl_egress_handle6[bin],
		             of_store.logicalPort_egress_handle[bin] + cnt.logicalPort_egress_handle[bin],
		             of_store.controlPlane_handle[bin] + cnt.controlPlane_handle[bin]);
	}

	struct overflow_store
	{
		uint64_t logicalPort_ingress_handle[YANET_TSC_BINS_N];
		uint64_t acl_ingress_handle4[YANET_TSC_BINS_N];
		uint64_t acl_ingress_handle6[YANET_TSC_BINS_N];
		uint64_t tun64_ipv4_handle[YANET_TSC_BINS_N];
		uint64_t tun64_ipv6_handle[YANET_TSC_BINS_N];
		uint64_t route_handle4[YANET_TSC_BINS_N];
		uint64_t route_handle6[YANET_TSC_BINS_N];

		uint64_t decap_handle[YANET_TSC_BINS_N];
		uint64_t nat64stateful_lan_handle[YANET_TSC_BINS_N];
		uint64_t nat64stateful_wan_handle[YANET_TSC_BINS_N];
		uint64_t nat64stateless_egress_handle[YANET_TSC_BINS_N];
		uint64_t nat64stateless_ingress_handle[YANET_TSC_BINS_N];
		uint64_t nat46clat_lan_handle[YANET_TSC_BINS_N];
		uint64_t nat46clat_wan_handle[YANET_TSC_BINS_N];
		uint64_t balancer_handle[YANET_TSC_BINS_N];

		uint64_t balancer_icmp_reply_handle[YANET_TSC_BINS_N];
		uint64_t balancer_icmp_forward_handle[YANET_TSC_BINS_N];
		uint64_t route_tunnel_handle4[YANET_TSC_BINS_N];
		uint64_t route_tunnel_handle6[YANET_TSC_BINS_N];
		uint64_t acl_egress_handle4[YANET_TSC_BINS_N];
		uint64_t acl_egress_handle6[YANET_TSC_BINS_N];
		uint64_t logicalPort_egress_handle[YANET_TSC_BINS_N];
		uint64_t controlPlane_handle[YANET_TSC_BINS_N];

		void handle_overflow(const tsc_deltas& cnt, const tsc_deltas& prev, int bin)
		{
			logicalPort_ingress_handle[bin] += (prev.logicalPort_ingress_handle[bin] > cnt.logicalPort_ingress_handle[bin]) << sizeof(uint16_t) * CHAR_BIT;
			acl_ingress_handle4[bin] += (prev.acl_ingress_handle4[bin] > cnt.acl_ingress_handle4[bin]) << sizeof(uint16_t) * CHAR_BIT;
			acl_ingress_handle6[bin] += (prev.acl_ingress_handle6[bin] > cnt.acl_ingress_handle6[bin]) << sizeof(uint16_t) * CHAR_BIT;
			tun64_ipv4_handle[bin] += (prev.tun64_ipv4_handle[bin] > cnt.tun64_ipv4_handle[bin]) << sizeof(uint16_t) * CHAR_BIT;
			tun64_ipv6_handle[bin] += (prev.tun64_ipv6_handle[bin] > cnt.tun64_ipv6_handle[bin]) << sizeof(uint16_t) * CHAR_BIT;
			route_handle4[bin] += (prev.route_handle4[bin] > cnt.route_handle4[bin]) << sizeof(uint16_t) * CHAR_BIT;
			route_handle6[bin] += (prev.route_handle6[bin] > cnt.route_handle6[bin]) << sizeof(uint16_t) * CHAR_BIT;

			decap_handle[bin] += (prev.decap_handle[bin] > cnt.decap_handle[bin]) << sizeof(uint16_t) * CHAR_BIT;
			nat64stateful_lan_handle[bin] += (prev.nat64stateful_lan_handle[bin] > cnt.nat64stateful_lan_handle[bin]) << sizeof(uint16_t) * CHAR_BIT;
			nat64stateful_wan_handle[bin] += (prev.nat64stateful_wan_handle[bin] > cnt.nat64stateful_wan_handle[bin]) << sizeof(uint16_t) * CHAR_BIT;
			nat64stateless_egress_handle[bin] += (prev.nat64stateless_egress_handle[bin] > cnt.nat64stateless_egress_handle[bin]) << sizeof(uint16_t) * CHAR_BIT;
			nat64stateless_ingress_handle[bin] += (prev.nat64stateless_ingress_handle[bin] > cnt.nat64stateless_ingress_handle[bin]) << sizeof(uint16_t) * CHAR_BIT;
			nat46clat_lan_handle[bin] += (prev.nat46clat_lan_handle[bin] > cnt.nat46clat_lan_handle[bin]) << sizeof(uint16_t) * CHAR_BIT;
			nat46clat_wan_handle[bin] += (prev.nat46clat_wan_handle[bin] > cnt.nat46clat_wan_handle[bin]) << sizeof(uint16_t) * CHAR_BIT;
			balancer_handle[bin] += (prev.balancer_handle[bin] > cnt.balancer_handle[bin]) << sizeof(uint16_t) * CHAR_BIT;

			balancer_icmp_reply_handle[bin] += (prev.balancer_icmp_reply_handle[bin] > cnt.balancer_icmp_reply_handle[bin]) << sizeof(uint16_t) * CHAR_BIT;
			balancer_icmp_forward_handle[bin] += (prev.balancer_icmp_forward_handle[bin] > cnt.balancer_icmp_forward_handle[bin]) << sizeof(uint16_t) * CHAR_BIT;
			route_tunnel_handle4[bin] += (prev.route_tunnel_handle4[bin] > cnt.route_tunnel_handle4[bin]) << sizeof(uint16_t) * CHAR_BIT;
			route_tunnel_handle6[bin] += (prev.route_tunnel_handle6[bin] > cnt.route_tunnel_handle6[bin]) << sizeof(uint16_t) * CHAR_BIT;
			acl_egress_handle4[bin] += (prev.acl_egress_handle4[bin] > cnt.acl_egress_handle4[bin]) << sizeof(uint16_t) * CHAR_BIT;
			acl_egress_handle6[bin] += (prev.acl_egress_handle6[bin] > cnt.acl_egress_handle6[bin]) << sizeof(uint16_t) * CHAR_BIT;
			logicalPort_egress_handle[bin] += (prev.logicalPort_egress_handle[bin] > cnt.logicalPort_egress_handle[bin]) << sizeof(uint16_t) * CHAR_BIT;
			controlPlane_handle[bin] += (prev.controlPlane_handle[bin] > cnt.controlPlane_handle[bin]) << sizeof(uint16_t) * CHAR_BIT;
		}
	};

	std::vector<std::tuple<uint32_t, tsc_deltas*, tsc_deltas, overflow_store>> worker_counters;
	table_t table;
};

void tsc_monitoring()
{
	tsc_monitoring_t monitoring{};
	monitoring.monitor();
}

}

}
