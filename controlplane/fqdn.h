#pragma once

#include "base.h"
#include "module.h"
#include "type.h"

#include "common/generation.h"

namespace fqdn
{

constexpr std::string_view vrf_all = "";

class generation_t
{
public:
	void update(const controlplane::base_t& base_prev,
	            const controlplane::base_t& base_next)
	{
		GCC_BUG_UNUSED(base_prev);

		vrf_fqdns = base_next.vrf_fqdns;

		for (const auto& [vrf, ip_fqdns] : vrf_fqdns)
		{
			auto it_vrf = vrf_ips[vrf];

			for (const auto& [ip, fqdns] : ip_fqdns)
			{
				for (const auto& fqdn : fqdns)
				{
					it_vrf[fqdn].emplace_back(ip);
				}
			}
		}
	}

public:
	std::map<std::string, ///< vrf
	         std::map<common::ip_address_t,
	                  std::vector<std::string>>>
	        vrf_fqdns;

	std::map<std::string, ///< vrf
	         std::map<std::string,
	                  std::vector<common::ip_address_t>>>
	        vrf_ips;
};

}

class fqdn_t : public module_t
{
public:
	eResult init() override;
	void reload_before() override;
	void reload(const controlplane::base_t& base_prev, const controlplane::base_t& base_next, common::idp::updateGlobalBase::request& globalbase) override;
	void reload_after() override;

	common::icp::resolve_ip_to_fqdn::response resolve_ip_to_fqdn(const common::icp::resolve_ip_to_fqdn::request& request) const;
	common::icp::resolve_fqdn_to_ip::response resolve_fqdn_to_ip(const common::icp::resolve_fqdn_to_ip::request& request) const;

protected:
	generation_manager<fqdn::generation_t> generations;
};
