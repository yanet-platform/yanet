#pragma once

#include <utility>

#include "base.h"
#include "common/idp.h"
#include "common/result.h"
#include "controlplane.h"

class config_converter_t
{
public:
	config_converter_t(cControlPlane* controlplane_ptr,
	                   controlplane::base_t baseNext,
	                   common::idp::limits::response limits) :
	        controlplane_ptr(controlplane_ptr),
	        baseNext(std::move(baseNext)),
	        limits(std::move(limits))
	{
	}

	[[nodiscard]] eResult process(uint32_t serial);

	[[nodiscard]] const controlplane::base_t& getBaseNext() const
	{
		return baseNext;
	}

	common::idp::updateGlobalBase::request& get_globalbase()
	{
		return globalbase;
	}

protected:
	void processLogicalPorts();
	void processRoutes();
	void processDecap();
	void processNat64stateful();
	void processNat64();
	void processNat46clat();
	void processTun64();
	void processBalancer();
	void processDregress();
	void processAcl();
	void buildAcl();

	void serializeLogicalPorts();
	void serializeRoutes();

	std::string checkLimit(size_t count, const std::string& limit, size_t multiplier(size_t));

	void convertToFlow(const std::string& nextModule, common::globalBase::tFlow& flow) const;
	[[nodiscard]] common::globalBase::tFlow convertToFlow(std::string nextModule) const;
	[[nodiscard]] common::globalBase::tFlow convertToFlow(std::string nextModule, const std::string& entryName) const;

	void acl_rules_route_local(controlplane::base::acl_t& acl, const std::string& next_module) const;
	void acl_rules_route_forward(controlplane::base::acl_t& acl, const std::string& next_module) const;
	void acl_rules_tun64(controlplane::base::acl_t& acl, const std::string& nextModule) const;
	void acl_rules_decap(controlplane::base::acl_t& acl, const std::string& nextModule) const;
	void acl_rules_nat64stateful(controlplane::base::acl_t& acl, const std::string& next_module) const;
	void acl_rules_nat64stateless(controlplane::base::acl_t& acl, const std::string& nextModule, const std::string& entry) const;
	void acl_rules_nat64stateless_ingress(controlplane::base::acl_t& acl, const std::string& nextModule) const;
	void acl_rules_nat64stateless_egress(controlplane::base::acl_t& acl, const std::string& nextModule) const;
	void acl_rules_nat46clat(controlplane::base::acl_t& acl, const std::string& next_module) const;
	void acl_rules_dregress(controlplane::base::acl_t& acl, const std::string& nextModule) const;
	void acl_rules_balancer(controlplane::base::acl_t& acl, const std::string& nextModule) const;
	void acl_rules_early_decap(controlplane::base::acl_t& acl) const;
	void acl_rules_balancer_icmp_reply(controlplane::base::acl_t& acl, const std::string& nextModule) const;
	void acl_rules_balancer_icmp_forward(controlplane::base::acl_t& acl, const std::string& nextModule) const;

private:
	cControlPlane* controlplane_ptr;

	controlplane::base_t baseNext;
	common::idp::updateGlobalBase::request globalbase;
	common::idp::limits::response limits;
};
