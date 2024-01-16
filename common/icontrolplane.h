#pragma once

#include <mutex>

#include <sys/un.h>

#include "icp.h"
#include "sendrecv.h"

namespace interface
{

class controlPlane
{
public:
	controlPlane() :
	        clientSocket(-1)
	{
	}

	~controlPlane()
	{
		if (clientSocket != -1)
		{
			close(clientSocket);
		}
	}

public:
	auto telegraf_unsafe() const
	{
		return get<common::icp::requestType::telegraf_unsafe, common::icp::telegraf_unsafe::response>();
	}

	auto telegraf_dregress() const
	{
		return get<common::icp::requestType::telegraf_dregress, common::icp::telegraf_dregress::response>();
	}

	auto telegraf_dregress_traffic() const
	{
		return get<common::icp::requestType::telegraf_dregress_traffic, common::icp::telegraf_dregress_traffic::response>();
	}

	auto telegraf_balancer_service() const
	{
		return get<common::icp::requestType::telegraf_balancer_service, common::icp::telegraf_balancer_service::response>();
	}

	auto telegraf_other() const
	{
		return get<common::icp::requestType::telegraf_other, common::icp::telegraf_other::response>();
	}

	auto telegraf_mappings() const
	{
		return get<common::icp::requestType::telegraf_mappings, common::icp::telegraf_mappings::response>();
	}

	common::icp::getPhysicalPorts::response getPhysicalPorts() const
	{
		return get<common::icp::requestType::getPhysicalPorts, common::icp::getPhysicalPorts::response>();
	}

	common::icp::getLogicalPorts::response getLogicalPorts() const
	{
		return get<common::icp::requestType::getLogicalPorts, common::icp::getLogicalPorts::response>();
	}

	common::icp::tun64_tunnels::response tun64_tunnels() const
	{
		return get<common::icp::requestType::tun64_tunnels, common::icp::tun64_tunnels::response>();
	}

	common::icp::tun64_prefixes::response tun64_prefixes() const
	{
		return get<common::icp::requestType::tun64_prefixes, common::icp::tun64_prefixes::response>();
	}

	common::icp::tun64_mappings::response tun64_mappings() const
	{
		return get<common::icp::requestType::tun64_mappings, common::icp::tun64_mappings::response>();
	}

	common::icp::getDecaps::response getDecaps() const
	{
		return get<common::icp::requestType::getDecaps, common::icp::getDecaps::response>();
	}

	auto nat64stateful_config() const
	{
		return get<common::icp::requestType::nat64stateful_config, common::icp::nat64stateful_config::response>();
	}

	auto nat64stateful_announce() const
	{
		return get<common::icp::requestType::nat64stateful_announce, common::icp::nat64stateful_announce::response>();
	}

	common::icp::getNat64statelesses::response getNat64statelesses() const
	{
		return get<common::icp::requestType::getNat64statelesses, common::icp::getNat64statelesses::response>();
	}

	auto route_config() const
	{
		return get<common::icp::requestType::route_config, common::icp::route_config::response>();
	}

	auto route_summary() const
	{
		return get<common::icp::requestType::route_summary, common::icp::route_summary::response>();
	}

	auto route_interface() const
	{
		return get<common::icp::requestType::route_interface, common::icp::route_interface::response>();
	}

	auto dregress_config() const
	{
		return get<common::icp::requestType::dregress_config, common::icp::dregress_config::response>();
	}

	auto balancer_config() const
	{
		return get<common::icp::requestType::balancer_config, common::icp::balancer_config::response>();
	}

	auto balancer_summary() const
	{
		return get<common::icp::requestType::balancer_summary, common::icp::balancer_summary::response>();
	}

	auto balancer_service(const common::icp::balancer_service::request& request) const
	{
		return get<common::icp::requestType::balancer_service, common::icp::balancer_service::response>(request);
	}

	auto balancer_real_find(const common::icp::balancer_real_find::request& request) const
	{
		return get<common::icp::requestType::balancer_real_find, common::icp::balancer_real_find::response>(request);
	}

	auto balancer_real(const common::icp::balancer_real::request& request) const
	{
		call<common::icp::requestType::balancer_real>(request);
	}

	auto balancer_real_flush() const
	{
		call<common::icp::requestType::balancer_real_flush>();
	}

	auto balancer_announce() const
	{
		return get<common::icp::requestType::balancer_announce, common::icp::balancer_announce::response>();
	}

	auto acl_unwind(const common::icp::acl_unwind::request& request) const
	{
		return get<common::icp::requestType::acl_unwind, common::icp::acl_unwind::response>(request);
	}

	auto acl_lookup(const common::icp::acl_lookup::request& request) const
	{
		return get<common::icp::requestType::acl_lookup, common::icp::acl_lookup::response>(request);
	}

	auto route_lookup(const common::icp::route_lookup::request& request) const
	{
		return get<common::icp::requestType::route_lookup, common::icp::route_lookup::response>(request);
	}

	auto route_get(const common::icp::route_get::request& request) const
	{
		return get<common::icp::requestType::route_get, common::icp::route_get::response>(request);
	}

	auto route_tunnel_lookup(const common::icp::route_tunnel_lookup::request& request) const
	{
		return get<common::icp::requestType::route_tunnel_lookup, common::icp::route_tunnel_lookup::response>(request);
	}

	auto route_tunnel_get(const common::icp::route_tunnel_get::request& request) const
	{
		return get<common::icp::requestType::route_tunnel_get, common::icp::route_tunnel_get::response>(request);
	}

	common::icp::getRibStats::response getRibStats() const
	{
		return get<common::icp::requestType::getRibStats, common::icp::getRibStats::response>();
	}

	common::icp::checkRibPrefixes::response checkRibPrefixes() const
	{
		return get<common::icp::requestType::checkRibPrefixes, common::icp::checkRibPrefixes::response>();
	}

	common::icp::getDefenders::response getDefenders() const
	{
		return get<common::icp::requestType::getDefenders, common::icp::getDefenders::response>();
	}

	common::icp::getPortStatsEx::response getPortStatsEx() const
	{
		return get<common::icp::requestType::getPortStatsEx, common::icp::getPortStatsEx::response>();
	}

	common::icp::getDecapPrefixes::response getDecapPrefixes() const
	{
		return get<common::icp::requestType::getDecapPrefixes, common::icp::getDecapPrefixes::response>();
	}

	common::icp::getNat64statelessTranslations::response getNat64statelessTranslations() const
	{
		return get<common::icp::requestType::getNat64statelessTranslations, common::icp::getNat64statelessTranslations::response>();
	}

	common::icp::getNat64statelessPrefixes::response getNat64statelessPrefixes() const
	{
		return get<common::icp::requestType::getNat64statelessPrefixes, common::icp::getNat64statelessPrefixes::response>();
	}

	void rib_update(const common::icp::rib_update::request& request) const
	{
		call<common::icp::requestType::rib_update>(request);
	}

	void rib_flush() const
	{
		call<common::icp::requestType::rib_flush>();
	}

	auto rib_summary() const
	{
		return get<common::icp::requestType::rib_summary, common::icp::rib_summary::response>();
	}

	auto rib_prefixes() const
	{
		return get<common::icp::requestType::rib_prefixes, common::icp::rib_prefixes::response>();
	}

	auto rib_lookup(const common::icp::rib_lookup::request& request) const
	{
		return get<common::icp::requestType::rib_lookup, common::icp::rib_lookup::response>(request);
	}

	auto rib_get(const common::icp::rib_get::request& request) const
	{
		return get<common::icp::requestType::rib_get, common::icp::rib_get::response>(request);
	}

	auto rib_save() const
	{
		return get<common::icp::requestType::rib_save, common::icp::rib_save::response>();
	}

	auto rib_load(const common::icp::rib_load::request& request) const
	{
		call<common::icp::requestType::rib_load>(request);
	}

	auto limit_summary() const
	{
		return get<common::icp::requestType::limit_summary, common::icp::limit_summary::response>();
	}

	auto controlplane_values() const
	{
		return get<common::icp::requestType::controlplane_values, common::icp::controlplane_values::response>();
	}

	auto controlplane_durations() const
	{
		return get<common::icp::requestType::controlplane_durations, common::icp::controlplane_durations::response>();
	}

	auto getFwList(const common::icp::getFwList::request& request) const
	{
		return get<common::icp::requestType::getFwList, common::icp::getFwList::response>(request);
	}

	auto getFwLabels() const
	{
		return get<common::icp::requestType::getFwLabels, common::icp::getFwLabels::response>();
	}

	void clearFWState() const
	{
		call<common::icp::requestType::clearFWState>();
	}

	common::icp::getSamples::response getSamples() const
	{
		return get<common::icp::requestType::getSamples, common::icp::getSamples::response>();
	}

	common::icp::getAclConfig::response getAclConfig(common::icp::getAclConfig::request request) const
	{
		return get<common::icp::requestType::getAclConfig, common::icp::getAclConfig::response>(request);
	}

	common::icp::loadConfig::response loadConfig(const common::icp::loadConfig::request& request) const
	{
		return get<common::icp::requestType::loadConfig, common::icp::loadConfig::response>(request);
	}

	void reloadConfig(const common::icp::loadConfig::request& request) const
	{
		call<common::icp::requestType::loadConfig>(request);
	}

	auto version() const
	{
		return get<common::icp::requestType::version, common::icp::version::response>();
	}

	auto nat46clat_config() const
	{
		return get<common::icp::requestType::nat46clat_config, common::icp::nat46clat_config::response>();
	}

	auto nat46clat_announce() const
	{
		return get<common::icp::requestType::nat46clat_announce, common::icp::nat46clat_announce::response>();
	}

	auto nat46clat_stats() const
	{
		return get<common::icp::requestType::nat46clat_stats, common::icp::nat46clat_stats::response>();
	}

	auto convert(const common::icp::convert::request& request) const
	{
		return get<common::icp::requestType::convert, common::icp::convert::response>(request);
	}

protected:
	void connectToControlPlane() const
	{
		if (clientSocket != -1)
		{
			/// already connected
			return;
		}

		clientSocket = socket(AF_UNIX, SOCK_STREAM, 0);
		if (clientSocket == -1)
		{
			throw std::string("socket(): ") + strerror(errno);
		}

		sockaddr_un address;
		memset((char*)&address, 0, sizeof(address));
		address.sun_family = AF_UNIX;
		strncpy(address.sun_path, common::icp::socketPath, sizeof(address.sun_path) - 1);
		address.sun_path[sizeof(address.sun_path) - 1] = 0;

		int ret = connect(clientSocket, (struct sockaddr*)&address, sizeof(address));
		if (ret == -1)
		{
			throw std::string("connect(): ") + strerror(errno);
		}
	}

	template<common::icp::requestType T, class Resp, class Req = std::tuple<>>
	Resp get(const Req& request = Req()) const
	{
		return std::get<Resp>(call<T>(request));
	}

	template<common::icp::requestType T, class Req = std::tuple<>>
	inline common::icp::response call(const Req& request = Req()) const
	{
		std::lock_guard<std::mutex> guard(mutex);
		connectToControlPlane();
		return common::sendAndRecv<common::icp::response>(clientSocket, common::icp::request(T, request));
	}

protected:
	mutable int clientSocket;
	mutable std::mutex mutex;
};

}
