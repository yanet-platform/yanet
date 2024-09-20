#pragma once

#include <map>
#include <thread>
#include <unordered_map>

#include <nlohmann/json.hpp>

#include "common/generation.h"
#include "common/idp.h"
#include "common/neighbor.h"

#include "hashtable.h"
#include "type.h"

namespace dataplane::neighbor
{

constexpr static uint16_t flag_is_ipv6 = 1 << 0;
constexpr static uint16_t flag_is_static = 1 << 1;

struct key
{
	tInterfaceId interface_id : 16;
	uint16_t flags;
	ipv6_address_t address;
};

static_assert(CONFIG_YADECAP_INTERFACES_SIZE <= 0xFFFF, "invalid size");

struct value
{
	rte_ether_addr ether_address;
	uint16_t flags;
	uint32_t last_update_timestamp;
};

//

using hashtable = hashtable_mod_dynamic<key, value, 16>;

//

class generation_interface
{
public:
	std::unordered_map<std::string, tInterfaceId> interface_name_to_id;
	std::unordered_map<tInterfaceId,
	                   std::tuple<std::string, ///< route_name
	                              std::string>> ///< interface_name
	        interface_id_to_name;
};

class generation_hashtable
{
public:
	std::map<tSocketId, dataplane::neighbor::hashtable::updater> hashtable_updater;
};

//

class module
{
public:
	module();

public:
	eResult init(cDataPlane* dataplane);

	void update_worker_base(const std::vector<std::tuple<tSocketId, dataplane::base::generation*>>& base_nexts);

	common::idp::neighbor_show::response neighbor_show() const;
	eResult neighbor_insert(const common::idp::neighbor_insert::request& request);
	eResult neighbor_remove(const common::idp::neighbor_remove::request& request);
	eResult neighbor_clear();
	eResult neighbor_flush();
	eResult neighbor_update_interfaces(const common::idp::neighbor_update_interfaces::request& request);
	common::idp::neighbor_stats::response neighbor_stats() const;

	void report(nlohmann::json& json);

protected:
	void main_thread();
	void netlink_thread();

	void resolve(const dataplane::neighbor::key& key);

protected:
	cDataPlane* dataplane;

	std::vector<std::thread> threads;

	generation_manager<dataplane::neighbor::generation_interface> generation_interface;
	generation_manager<dataplane::neighbor::generation_hashtable, eResult> generation_hashtable;

	common::neighbor::stats stats;
};

}
