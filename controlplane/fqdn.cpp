#include "fqdn.h"
#include "controlplane.h"

eResult fqdn_t::init()
{
	controlPlane->register_command(common::icp::requestType::resolve_ip_to_fqdn, [this](const common::icp::request& request) {
		return resolve_ip_to_fqdn(std::get<common::icp::resolve_ip_to_fqdn::request>(std::get<1>(request)));
	});

	controlPlane->register_command(common::icp::requestType::resolve_fqdn_to_ip, [this](const common::icp::request& request) {
		return resolve_fqdn_to_ip(std::get<common::icp::resolve_fqdn_to_ip::request>(std::get<1>(request)));
	});

	return eResult::success;
}

void fqdn_t::reload_before()
{
	generations.next_lock();
}

void fqdn_t::reload(const controlplane::base_t& base_prev,
                    const controlplane::base_t& base_next,
                    [[maybe_unused]] common::idp::updateGlobalBase::request& globalbase)
{
	generations.next().update(base_prev, base_next);
}

void fqdn_t::reload_after()
{
	generations.switch_generation();
	generations.next_unlock();
}

common::icp::resolve_ip_to_fqdn::response fqdn_t::resolve_ip_to_fqdn(const common::icp::resolve_ip_to_fqdn::request& request) const
{
	const auto& [request_vrf_orig, request_ip] = request;

	auto current_guard = generations.current_lock_guard();
	const auto& current = generations.current();

	auto request_vrf = request_vrf_orig;
	for (;;)
	{
		auto it_vrf = current.vrf_fqdns.find(request_vrf);
		if (it_vrf != current.vrf_fqdns.end())
		{
			auto it_fqdn = it_vrf->second.find(request_ip);
			if (it_fqdn != it_vrf->second.end())
			{
				return it_fqdn->second;
			}
		}

		if (request_vrf == fqdn::vrf_all)
		{
			break;
		}

		request_vrf = fqdn::vrf_all;
	}

	return {}; ///< not found
}

common::icp::resolve_fqdn_to_ip::response fqdn_t::resolve_fqdn_to_ip(const common::icp::resolve_fqdn_to_ip::request& request) const
{
	const auto& [request_vrf_orig, request_fqdn] = request;

	auto current_guard = generations.current_lock_guard();
	const auto& current = generations.current();

	auto request_vrf = request_vrf_orig;
	for (;;)
	{
		auto it_vrf = current.vrf_ips.find(request_vrf);
		if (it_vrf != current.vrf_ips.end())
		{
			auto it_ip = it_vrf->second.find(request_fqdn);
			if (it_ip != it_vrf->second.end())
			{
				return it_ip->second;
			}
		}

		if (request_vrf == fqdn::vrf_all)
		{
			break;
		}

		request_vrf = fqdn::vrf_all;
	}

	return {}; ///< not found
}
