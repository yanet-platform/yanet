#pragma once

#include <atomic>
#include <functional>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <type_traits>
#include <vector>

#include <nlohmann/json.hpp>

#include "common/generation.h"
#include "common/icp.h"
#include "common/idataplane.h"
#include "common/idp.h"
#include "common/result.h"
#include "libprotobuf/controlplane.pb.h"

#include "balancer.h"
#include "base.h"
#include "counter.h"
#include "dregress.h"
#include "durations.h"
#include "fqdn.h"
#include "isystem.h"
#include "memory_manager.h"
#include "module.h"
#include "nat46clat.h"
#include "nat64stateful.h"
#include "route.h"
#include "tun64.h"
#include "type.h"

class cControlPlane
{
public:
	cControlPlane();
	~cControlPlane();

	eResult init(const std::string& jsonFilePath);
	void start();
	void stop();
	void join();

	eResult reloadConfig();

	eResult getPhysicalPortName(const tPortId& portId, std::string& name) const;

	template<typename T_function>
	void register_command(const common::icp::requestType& type, const T_function& function)
	{
		/// @todo: check exist

		if constexpr (std::is_invocable_r_v<common::icp::response, decltype(function), common::icp::request>)
		{
			commands[type] = function;
		}
		else if constexpr (std::is_invocable_r_v<void, decltype(function), common::icp::request>)
		{
			commands[type] = [function](const common::icp::request& request) {
				function(request);
				return std::tuple<>{};
			};
		}
		else if constexpr (std::is_invocable_r_v<common::icp::response, decltype(function)>)
		{
			commands[type] = [function](const common::icp::request& request) {
				(void)request;
				return function();
			};
		}
		else if constexpr (std::is_invocable_r_v<void, decltype(function)>)
		{
			commands[type] = [function](const common::icp::request& request) {
				(void)request;
				function();
				return std::tuple<>{};
			};
		}
		else
		{
			/// compile time error
			function.cannot_be_registered_with_that_signature();
		}
	}

	template<typename type_t>
	void register_counter(type_t& counters)
	{
		counters.init(&counter_manager);
	}

	void inline forEachSocket(const std::function<void(const tSocketId& socketId)>& function) const
	{
		for (const auto& socketId : sockets)
		{
			function(socketId);
		}
	}

protected: /** commands */
	common::icp::getPhysicalPorts::response getPhysicalPorts() const;
	common::icp::getLogicalPorts::response getLogicalPorts() const;
	common::icp::getDecaps::response getDecaps() const;
	common::icp::getNat64statelesses::response getNat64statelesses() const;
	common::icp::getDefenders::response getDefenders() const;
	common::icp::getPortStatsEx::response getPortStatsEx() const;
	common::icp::limit_summary::response limit_summary() const;
	common::icp::acl_unwind::response acl_unwind(const common::icp::acl_unwind::request& request) const;
	common::icp::acl_lookup::response acl_lookup(const common::icp::acl_lookup::request& request) const;
	common::icp::controlplane_values::response controlplane_values() const;

	common::icp::getDecapPrefixes::response command_getDecapPrefixes();
	common::icp::getNat64statelessTranslations::response command_getNat64statelessTranslations();
	common::icp::getNat64statelessPrefixes::response command_getNat64statelessPrefixes();
	common::icp::getFwLabels::response command_getFwLabels();
	common::icp::getFwList::response command_getFwList(const common::icp::getFwList::request& request);
	void command_clearFWState();
	common::icp::getSamples::response command_getSamples();
	common::icp::getAclConfig::response command_getAclConfig(common::icp::getAclConfig::request);
	common::icp::loadConfig::response command_loadConfig(const common::icp::loadConfig::request& request);
	common::icp::version::response command_version();
	common::icp::convert::response command_convert(const common::icp::convert::request& request);

	common::icp::convert::response convert_logical_module();

protected:
	/// @todo: config_t::load()
	eResult loadConfig(const std::string& rootFilePath, const nlohmann::json& rootJson, const std::map<std::string, nlohmann::json>& jsons = {});

	void addConfig(uint32_t serial, const controlplane::base_t& config);

	void main_thread();

protected:
	friend class telegraf_t;
	friend class controlplane::module::bus;
	friend class controlplane::module::protoBus;
	friend class rib_t;
	friend class dregress_t;
	friend class route_t; ///< @todo: delete
	friend class balancer_t;
	friend class tun64_t;
	friend class config_converter_t;

	volatile bool flagStop;

	interface::dataPlane dataPlane;
	interface::system system;

	/// read only after init {
	std::string jsonFilePath;

	std::vector<std::thread> threads;

	std::vector<cModule*> modules;
	std::map<common::icp::requestType,
	         std::function<common::icp::response(const common::icp::request&)>>
	        commands;
	std::map<std::string, google::protobuf::Service*> services;

	common::idp::getConfig::response dataPlaneConfig;
	std::set<tSocketId> sockets;
	/// }

	dregress_t dregress;
	route_t route;
	balancer_t balancer;
	tun64_t tun64;
	fqdn_t fqdn;
	durations_t durations;
	nat64stateful_t nat64stateful;
	nat46clat::manager nat46clat;
	controlplane::memory_manager::memory_manager memory_manager;

	counter_manager_t counter_manager;

	generation_manager<controlplane::base_t> generations; ///< @todo: move to new class

	std::mutex configs_mutex;
	std::map<uint32_t, controlplane::base_t> configs;

	/// aclCountersDelta_mutex {
	mutable std::shared_mutex aclCountersDelta_mutex;
	std::vector<uint64_t> aclCountersDelta;
	/// }

	std::mutex reload_mutex;

	uint64_t loadConfig_done = 0;
	uint64_t loadConfig_failed = 0;
	bool loadConfigStatus = false; // true - last load was ok

private:
	/// used only in loadConfig()
	controlplane::base_t base;

	void register_service(google::protobuf::Service* service);
};
