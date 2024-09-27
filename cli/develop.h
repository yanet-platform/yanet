#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <sys/shm.h>
#include <thread>
#include <vector>

#include "common/idataplane.h"
#include "common/sdpclient.h"
#include "common/shared_memory.h"
#include "common/tsc_deltas.h"
#include "common/tuple.h"

#include "helper.h"

namespace develop::dataplane
{

static void printValue(const common::idp::value& value)
{
	const auto& [type, interface] = value;
	std::ostringstream oss;
	using common::globalBase::eNexthopType;

	switch (type)
	{
		case eNexthopType::drop:
			oss << "  drop\n";
			break;
		case eNexthopType::interface:
			for (const auto& [interfaceId, transport, service] : interface)
			{
				const auto& [transport_label, transport_exp] = transport;
				const auto& [service_label, service_exp] = service;

				if (transport_label != common::unlabelled)
				{
					if (service_label != common::unlabelled)
					{
						oss << "  interfaceId: " << interfaceId
						    << ",\ttransport: [label: " << transport_label
						    << ", exp: " << transport_exp
						    << "],\tservice: [label: " << service_label
						    << ", exp: " << service_exp << "]\n";
					}
					else
					{
						oss << "  interfaceId: " << interfaceId
						    << ",\ttransport: [label: " << transport_label
						    << ", exp: " << transport_exp << "]\n";
					}
				}
				else
				{
					oss << "  interfaceId: " << interfaceId << "\n";
				}
			}
			break;
		case eNexthopType::controlPlane:
			oss << "  controlPlane\n";
			break;
		default:
			oss << "  error\n";
	}

	std::cout << oss.str();
}

template<typename T>
static void lpmLookupAddress(const T& address)
{
	interface::dataPlane dataPlane;

	const auto& response = [&]() {
		if constexpr (std::is_same_v<T, common::ipv4_address_t>)
		{
			return dataPlane.lpm4LookupAddress(address);
		}
		else if constexpr (std::is_same_v<T, common::ipv6_address_t>)
		{
			return dataPlane.lpm6LookupAddress(address);
		}
		else
		{
			static_assert(utils::always_false<T>::value,
			              "lpmLookupAddress cannot be used with types other than ipv4/6_address");
		}
	}();

	for (const auto& [socketId, entry] : response)
	{
		const auto& [found, valueId, value] = entry;
		std::cout << "[socketId: " << socketId << "] " << address.toString() << " -> ";

		if (found)
		{
			std::cout << "valueId: " << valueId << '\n';
			printValue(value);
		}
		else
		{
			std::cout << "not found\n";
		}
	}
}

inline void lpm4LookupAddress(const common::ipv4_address_t& address)
{
	lpmLookupAddress(address);
}

inline void lpm6LookupAddress(const common::ipv6_address_t& address)
{
	lpmLookupAddress(address);
}

inline void getErrors()
{
	interface::dataPlane dataPlane;

	std::cout << "errors:\n";
	for (const auto& [name, counter] : dataPlane.getErrors())
	{
		std::cout << "  (" << counter.value << ") " << name << '\n';
	}
}

inline void getReport()
{
	interface::dataPlane dataPlane;
	std::cout << dataPlane.getReport() << '\n';
}

inline void counter(uint32_t counter_id, const std::optional<uint32_t>& range_size)
{
	std::vector<tCounterId> counter_ids{counter_id};

	if (range_size.has_value() && range_size.value() > 0)
	{
		for (uint32_t offset = 0; offset < range_size.value() - 1; offset++)
		{
			counter_ids.emplace_back(counter_id + offset + 1);
		}
	}

	const auto& response = common::sdp::SdpClient::GetCounters(counter_ids);

	table_t table;
	table.insert("counter_id", "value");

	for (uint32_t i = 0; i < counter_ids.size(); i++)
	{
		table.insert(counter_ids[i], response[i]);
	}

	table.print();
}

using namespace ::dataplane::perf;
struct tsc_monitoring_t
{
	void connect_shm()
	{
		interface::dataPlane dataplane;
		const auto& response = dataplane.get_shm_tsc_info();
		std::map<key_t, void*> ipc_cache;

		for (const auto& [core, socket, ipc_key, offset] : response)
		{
			YANET_GCC_BUG_UNUSED(socket);
			if (ipc_cache.find(ipc_key) == ipc_cache.end())
			{
				auto&& [shmaddr, size] = common::ipc::SharedMemory::OpenBufferKey(ipc_key, false);
				YANET_GCC_BUG_UNUSED(size);

				if (shmaddr == nullptr)
				{
					throw std::system_error(errno, std::generic_category(), "Opening an existing buffer in shared memory failed");
				}

				ipc_cache[ipc_key] = shmaddr;
			}

			auto counter_addr = reinterpret_cast<tsc_deltas*>(
			        reinterpret_cast<intptr_t>(ipc_cache[ipc_key]) + offset);
			worker_counters.emplace_back(core, counter_addr, tsc_deltas{}, overflow_store{});
		}
	}

	void monitor()
	{
		connect_shm();
		const int header_interval = 4;

		for (int iter = 0;; ++iter)
		{
			bool render_header = (iter % header_interval == 0);

			if (render_header)
			{
				insert_header();
			}

			for (auto& [core_id, counter, previous_value, overflow_store] : worker_counters)
			{
				const auto& counter_copy = *counter;
				for (int bin = 0; bin < YANET_TSC_BINS_N; ++bin)
				{
					overflow_store.handle_overflow(counter_copy, previous_value, bin);

					if (render_header)
					{
						insert_bin(counter_copy, overflow_store, bin, core_id);
					}
				}

				previous_value = counter_copy;
			}

			if (render_header)
			{
				table.render();
			}

			std::this_thread::sleep_for(std::chrono::milliseconds(250));
		}
	}

private:
	struct overflow_store
	{
		template<typename T>
		static auto make_tuple(T& obj)
		{
			return std::tie(obj.logicalPort_ingress_handle,
			                obj.acl_ingress_handle4,
			                obj.acl_ingress_handle6,
			                obj.tun64_ipv4_handle,
			                obj.tun64_ipv6_handle,
			                obj.route_handle4,
			                obj.route_handle6,
			                obj.decap_handle,
			                obj.nat64stateful_lan_handle,
			                obj.nat64stateful_wan_handle,
			                obj.nat64stateless_egress_handle,
			                obj.nat64stateless_ingress_handle,
			                obj.nat46clat_lan_handle,
			                obj.nat46clat_wan_handle,
			                obj.balancer_handle,
			                obj.balancer_icmp_reply_handle,
			                obj.balancer_icmp_forward_handle,
			                obj.route_tunnel_handle4,
			                obj.route_tunnel_handle6,
			                obj.acl_egress_handle4,
			                obj.acl_egress_handle6,
			                obj.logicalPort_egress_handle,
			                obj.controlPlane_handle);
		}

		using CountersArray = std::array<uint64_t, YANET_TSC_BINS_N>;

		CountersArray logicalPort_ingress_handle{};
		CountersArray acl_ingress_handle4{};
		CountersArray acl_ingress_handle6{};
		CountersArray tun64_ipv4_handle{};
		CountersArray tun64_ipv6_handle{};
		CountersArray route_handle4{};
		CountersArray route_handle6{};

		CountersArray decap_handle{};
		CountersArray nat64stateful_lan_handle{};
		CountersArray nat64stateful_wan_handle{};
		CountersArray nat64stateless_egress_handle{};
		CountersArray nat64stateless_ingress_handle{};
		CountersArray nat46clat_lan_handle{};
		CountersArray nat46clat_wan_handle{};
		CountersArray balancer_handle{};

		CountersArray balancer_icmp_reply_handle{};
		CountersArray balancer_icmp_forward_handle{};
		CountersArray route_tunnel_handle4{};
		CountersArray route_tunnel_handle6{};
		CountersArray acl_egress_handle4{};
		CountersArray acl_egress_handle6{};
		CountersArray logicalPort_egress_handle{};
		CountersArray controlPlane_handle{};

		auto as_tuple()
		{
			return make_tuple(*this);
		}

		[[nodiscard]] auto as_tuple() const
		{
			return make_tuple(*this);
		}

		void handle_overflow(const tsc_deltas& cnt, const tsc_deltas& prev, int bin)
		{
			auto this_tuple = as_tuple();
			auto cnt_tuple = cnt.as_tuple();
			auto prev_tuple = prev.as_tuple();

			auto op = [&](auto& this_member, const auto& cnt_member, const auto& prev_member) {
				this_member[bin] += (prev_member[bin] > cnt_member[bin]) << (sizeof(uint16_t) * CHAR_BIT);
			};

			utils::zip_apply(op, this_tuple, cnt_tuple, prev_tuple);
		}
	};

	std::vector<std::tuple<uint32_t, tsc_deltas*, tsc_deltas, overflow_store>> worker_counters;
	table_t table;

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
		constexpr std::size_t tuple_size = std::tuple_size_v<decltype(cnt.as_tuple())>;
		// The total size of the row will be 2 fixed elements (core_id and iter_num) plus tuple_size
		std::array<std::string, 2 + tuple_size> row;

		row[0] = (bin == 0) ? std::to_string(core_id) : std::string{};
		row[1] = (bin == 0) ? std::to_string(cnt.iter_num) : std::string{};

		auto cnt_tuple = cnt.as_tuple();
		auto of_store_tuple = of_store.as_tuple();

		std::size_t index = 2; // Start after core_id and iter_num
		auto op = [&](const auto& of_store_member, const auto& cnt_member) mutable {
			row[index++] = std::to_string(of_store_member[bin] + cnt_member[bin]);
		};

		utils::zip_apply(op, of_store_tuple, cnt_tuple);

		table.insert(row.begin(), row.end());
	}
};

inline void tsc_monitoring()
{
	tsc_monitoring_t monitoring{};
	monitoring.monitor();
}

}
