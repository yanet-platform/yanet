#pragma once

#include <string>

#include "common/controlplaneconfig.h"

#include "base.h"

class config_parser_t
{
public:
	config_parser_t(common::idp::getConfig::response dataPlaneConfig) :
	        dataPlaneConfig(dataPlaneConfig)
	{}

	controlplane::base_t loadConfig(const std::string& rootFilePath, const nlohmann::json& rootJson, const std::map<std::string, nlohmann::json>& jsons = {});

protected:
	tPortId getPhysicalPortId(const std::string& name) const;
	void loadConfig_logicalPort(controlplane::base_t& baseNext, const std::string& moduleId, const nlohmann::json& moduleJson);
	void loadConfig_route(controlplane::base_t& baseNext, const std::string& moduleId, const nlohmann::json& moduleJson, const std::string& rootFilePath, const std::map<std::string, nlohmann::json>& jsons);
	void loadConfig_route_peers(controlplane::base_t& baseNext, controlplane::route::config_t& route, const nlohmann::json& json, const std::string& rootFilePath, const std::map<std::string, nlohmann::json>& jsons);
	void loadConfig_decap(controlplane::base_t& baseNext, const std::string& moduleId, const nlohmann::json& moduleJson);
	void loadConfig_nat64stateful(controlplane::base_t& baseNext, const std::string& moduleId, const nlohmann::json& moduleJson, const std::string& rootFilePath, const std::map<std::string, nlohmann::json>& jsons);
	void loadConfig_nat64stateless(controlplane::base_t& baseNext, const std::string& moduleId, const nlohmann::json& moduleJson, const std::string& rootFilePath, const std::map<std::string, nlohmann::json>& jsons);
	void loadConfig_nat64stateless_translations(controlplane::base_t& baseNext, controlplane::base::nat64stateless_t& nat64stateless, const nlohmann::json& translationsJson, const std::string& rootFilePath, const std::map<std::string, nlohmann::json>& jsons);
	void loadConfig_nat46clat(controlplane::base_t& baseNext, const std::string& moduleId, const nlohmann::json& moduleJson, const std::string& rootFilePath, const std::map<std::string, nlohmann::json>& jsons);
	void loadConfig_acl(controlplane::base_t& baseNext, const std::string& moduleId, const nlohmann::json& moduleJson, const std::string& rootFilePath);
	void loadConfig_dregress(controlplane::base_t& baseNext, const std::string& moduleId, const nlohmann::json& moduleJson, const std::string& rootFilePath, const std::map<std::string, nlohmann::json>& jsons);
	void loadConfig_dregress_communities(controlplane::base_t& baseNext, controlplane::dregress::config_t& dregress, const nlohmann::json& json, const std::string& rootFilePath, const std::map<std::string, nlohmann::json>& jsons);
	void loadConfig_localPrefixes(controlplane::base_t& baseNext, std::set<common::ip_prefix_t>& localPrefixes, const nlohmann::json& json, const std::string& rootFilePath, const std::map<std::string, nlohmann::json>& jsons);
	void loadConfig_ourAs(controlplane::base_t& baseNext, std::set<uint32_t>& ourAs, const nlohmann::json& json, const std::string& rootFilePath, const std::map<std::string, nlohmann::json>& jsons);
	void loadConfig_balancer(controlplane::base_t& baseNext, const std::string& moduleId, const nlohmann::json& moduleJson, const std::string& rootFilePath, const std::map<std::string, nlohmann::json>& jsons);
	void loadConfig_balancer_services(controlplane::base_t& baseNext, controlplane::balancer::config_t& balancer, const nlohmann::json& json, const std::string& rootFilePath, const std::map<std::string, nlohmann::json>& jsons);
	void loadConfig_balancer_unrdup(controlplane::balancer::config_t& balancer, const std::string& rootFilePath, const std::string& unrdup_cfg_path);
	void loadConfig_tun64(controlplane::base_t& baseNext, const std::string& moduleId, const nlohmann::json& moduleJson, const std::string& rootFilePath, const std::map<std::string, nlohmann::json>& jsons);
	void loadConfig_tun64mappings(controlplane::base_t& baseNext, controlplane::tun64::config_t& tunnel, const nlohmann::json& mappingsJson, const std::string& rootFilePath, const std::map<std::string, nlohmann::json>& jsons);

	void loadConfig_variables(controlplane::base_t& baseNext, const nlohmann::json& json);
	void loadConfig_fqdns(controlplane::base_t& baseNext, const nlohmann::json& json, const std::string& rootFilePath, const std::map<std::string, nlohmann::json>& jsons);
	void loadConfig_rib(controlplane::base_t& baseNext, const nlohmann::json& json);
	void loadConfig_memory_group(common::memory_manager::memory_group& memory_group, const nlohmann::json& json);

private:
	common::idp::getConfig::response dataPlaneConfig;
};
