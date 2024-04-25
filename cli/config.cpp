#include "config.h"

#include <fstream>
#include <iostream>
#include <json.hpp>
#include <tuple>
#include <unistd.h>

#include "common/icontrolplane.h"
#include "common/type.h"

namespace
{

// TODO: replace this path to config by retreived from controlplane
constexpr char CONFIG_PATH[] = "/etc/yanet/controlplane.conf";
constexpr char TMP_CONFIG_PATH[] = "/etc/yanet/controlplane.conf.tmp";

// loads config from fs and parse it
nlohmann::json loadConfig()
{
	std::ifstream stream(CONFIG_PATH);
	if (!stream.is_open())
	{
		std::ostringstream error;
		error << "can't open config file '" << CONFIG_PATH << "': " << strerror(errno);
		throw error.str();
	}

	return nlohmann::json::parse(stream);
}

// saves config to fs and send command to controlplane for reloading it
void saveConfig(const nlohmann::json& root)
{
	std::ofstream stream(TMP_CONFIG_PATH);
	if (!stream.is_open())
	{
		std::ostringstream error;
		error << "can't open config file '" << TMP_CONFIG_PATH << "': " << strerror(errno);
		throw error.str();
	}

	stream << root.dump(2);
	stream.close();

	unlink(CONFIG_PATH);
	rename(TMP_CONFIG_PATH, CONFIG_PATH);

	config::reload();
}

// gets module from json by name
nlohmann::json& getModule(nlohmann::json& root,
                          const std::string& moduleName)
{
	auto modules = root.find("modules");
	if (modules == root.end())
	{
		throw std::string("config doesn't have 'modules'");
	}

	auto module = modules->find(moduleName);
	if (module == modules->end())
	{
		std::ostringstream error;
		error << "config doesn't have module with name '" << moduleName << "'";
		throw error.str();
	}
	return *module;
}

// checks that module object has type field with expected value
void checkModuleType(const nlohmann::json& module,
                     const std::string& expectedType)
{
	std::string type = module["type"];
	if (type != expectedType)
	{
		std::ostringstream error;
		error << "module has inappropriate type '" << type << "'";
		throw error.str();
	}
}

// allows announce for prefix within specified section in config (@prefixes)
bool allowPrefix(nlohmann::json& prefixes,
                 const std::string& prefixRaw,
                 const std::string& announceRaw)
{
	// try to find prefix in the current config and add announce to it
	for (auto it = prefixes.begin(); it != prefixes.end(); ++it)
	{
		// prefix could be either a string (for old configs support) or an object
		if (it->is_string())
		{
			// if prefix is a string it means that this prefix has only one announce which is equal to the prefix
			const auto& curPrefix = it->get_ref<const std::string&>();
			// skip prefixes other than @prefixRaw
			if (curPrefix != prefixRaw)
			{
				continue;
			}

			// prefix and announce are already set
			if (curPrefix == announceRaw)
			{
				return false;
			}

			// replace simple string prefix by prefix/announces object
			prefixes.erase(it);
			prefixes.emplace_back(nlohmann::json{
			        {"prefix", prefixRaw},
			        {"announces", nlohmann::json::array_t{prefixRaw, announceRaw}},
			});
			return true;
		}
		else if (it->is_object())
		{
			const auto& curPrefix = [&]() {
				auto prefixIt = it->find("prefix");
				if (prefixIt == it->end())
					throw std::string{"invalid prefix item. Object doesn't 'prefix' field."};
				return prefixIt->get_ref<const std::string&>();
			}();

			// skip prefixes other than @prefixRaw
			if (curPrefix != prefixRaw)
			{
				continue;
			}

			const auto& [announces, inserted] = it->emplace("announces", nlohmann::json::array_t{announceRaw});
			// check whether the announce was insterted by this emplace
			if (inserted)
			{
				return true;
			}

			// check whether current announces includes announceRaw
			for (auto announceIt = announces->begin(); announceIt != announces->end(); ++announceIt)
			{
				// sanity check that announce has string type
				if (!announceIt->is_string())
				{
					throw std::string{"invalid type of prefix item announce. Should be string"};
				}

				// announce already presented within the prefix
				if (announceIt->get_ref<const std::string&>() == announceRaw)
				{
					return false;
				}
			}

			// @announceRaw wasn't found within current announces, so add it
			announces->emplace_back(announceRaw);
			return true;
		}
		else
		{
			throw std::string{"invalid type of prefix item. Should be either object or string"};
		}
	}

	// @prefixRaw wasn't found within current prefixes, so add it
	prefixes.emplace_back(nlohmann::json{
	        {"prefix", prefixRaw},
	        {"announces", nlohmann::json::array_t{announceRaw}},
	});

	return true;
}

// diallows announce for prefix within specified section in config (@prefixes)
bool disallowPrefix(nlohmann::json& prefixes,
                    const std::string& prefixRaw,
                    const std::string& announceRaw)
{
	for (auto it = prefixes.begin(); it != prefixes.end(); ++it)
	{
		// prefix could be either a string (for old configs support) or an object
		if (it->is_string())
		{
			// if prefix is a string it means that this prefix has only one announce which is equal to the prefix
			const auto& curPrefix = it->get_ref<std::string&>();
			// skip prefixes other than @prefixRaw
			if (curPrefix != prefixRaw)
			{
				continue;
			}

			if (curPrefix != announceRaw)
			{
				throw std::string{"prefix doesn't have such announce"};
			}

			// replace simple string prefix by prefix/announces object with empty announces because
			// the only prefix was disallowed
			prefixes.erase(it);
			prefixes.emplace_back(nlohmann::json{
			        {"prefix", prefixRaw},
			        {"announces", nlohmann::json::array_t{}},
			});
			return true;
		}
		else if (it->is_object())
		{
			const auto& curPrefix = [&]() {
				auto prefixIt = it->find("prefix");
				if (prefixIt == it->end())
					throw std::string{"invalid prefix item. Object doesn't 'prefix' field."};
				return prefixIt->get_ref<const std::string&>();
			}();

			// skip prefixes other than @prefixRaw
			if (curPrefix != prefixRaw)
			{
				continue;
			}

			auto announces = it->find("announces");
			if (announces == it->end())
			{
				throw std::string("prefix doesn't have any announce");
			}

			for (auto announceIt = announces->begin(); announceIt != announces->end(); ++announceIt)
			{
				if (!announceIt->is_string())
				{
					throw std::string{"invalid type of prefix item announce. Should be string"};
				}

				if (announceIt->get_ref<const std::string&>() == announceRaw)
				{
					announces->erase(announceIt);
					return true;
				}
			}

			throw std::string{"prefix doesn't have such announce"};
		}
		else
		{
			throw std::string{"invalid type of prefix item. Should be either object or string"};
		}
	}

	throw std::string{"prefix doesn't have such prefix"};
}

// removes whole prefix from specified section in config (@prefixes)
bool removePrefix(nlohmann::json& prefixes,
                  const std::string& prefixRaw)
{
	for (auto it = prefixes.begin(); it != prefixes.end(); ++it)
	{
		// prefix could be either a string (for old configs support) or an object
		if (it->is_string())
		{
			// skip prefixes other than @prefixRaw
			if (it->get_ref<const std::string&>() != prefixRaw)
			{
				continue;
			}

			prefixes.erase(it);
			return true;
		}
		else if (it->is_object())
		{
			const auto& curPrefix = [&]() {
				auto prefixIt = it->find("prefix");
				if (prefixIt == it->end())
					throw std::string{"invalid prefix item. Object doesn't 'prefix' field."};
				return prefixIt->get_ref<const std::string&>();
			}();

			// skip prefixes other than @prefixRaw
			if (curPrefix != prefixRaw)
			{
				continue;
			}

			prefixes.erase(it);
			return true;
		}
		else
		{
			throw std::string{"invalid type of prefix item. Should be either object or string"};
		}
	}

	throw std::string{"module doesn't have such prefix"};
}

void validateIPv4Prefix(const std::string& prefixRaw, const std::string& announceRaw)
{
	auto parse = [](const std::string& value, std::string name) {
		common::ipv4_prefix_t tmp{value};
		if (!tmp.isValid())
		{
			std::ostringstream error;
			error << "Specified " << name << ": '" << value << "' is not a valid IPv4 prefix";
			throw error.str();
		}

		return tmp;
	};

	auto prefix = parse(prefixRaw, "prefix");
	auto announce = parse(announceRaw, "announce");

	if (!announce.subnetOf(prefix))
	{
		std::ostringstream error;
		error << "Specified announce: '" << announceRaw << "' is not a subnet of prefix: '" << prefixRaw << "'";
		throw error.str();
	}
}

void validateIPv6Prefix(const std::string& prefixRaw, const std::string& announceRaw)
{
	auto parse = [](const std::string& value, std::string name) {
		common::ipv6_prefix_t tmp{value};
		if (!tmp.isValid())
		{
			std::ostringstream error;
			error << "Specified " << name << ": '" << value << "' is not a valid IPv6 prefix";
			throw error.str();
		}

		return tmp;
	};

	auto prefix = parse(prefixRaw, "prefix");
	auto announce = parse(announceRaw, "announce");

	if (!announce.subnetOf(prefix))
	{
		std::ostringstream error;
		error << "Specified announce: '" << announceRaw << "' is not a subnet of prefix: '" << prefixRaw << "'";
		throw error.str();
	}
}

} /* namespace */

namespace config
{

namespace decap
{

void allow(const std::string& module,
           const std::string& prefixRaw,
           const std::string& announceRaw)
{
	validateIPv6Prefix(prefixRaw, announceRaw);

	auto root = loadConfig();

	auto& decap = getModule(root, module);
	checkModuleType(decap, "decap");

	const auto& [prefixes, inserted] = decap.emplace("ipv6DestinationPrefixes", nlohmann::json::array_t{});
	(void)inserted;

	if (allowPrefix(*prefixes, prefixRaw, announceRaw))
	{
		saveConfig(root);
	}
}

void disallow(const std::string& module,
              const std::string& prefixRaw,
              const std::string& announceRaw)
{
	auto root = loadConfig();

	auto& decap = getModule(root, module);
	checkModuleType(decap, "decap");

	auto prefixes = decap.find("ipv6DestinationPrefixes");
	if (prefixes == decap.end())
	{
		throw std::string("module config doesn't have 'ipv6DestinationPrefixes'");
	}

	if (disallowPrefix(*prefixes, prefixRaw, announceRaw))
	{
		saveConfig(root);
	}
}

void remove(const std::string& module,
            const std::string& prefixRaw)
{
	auto root = loadConfig();

	auto& decap = getModule(root, module);
	checkModuleType(decap, "decap");

	auto prefixes = decap.find("ipv6DestinationPrefixes");
	if (prefixes == decap.end())
	{
		throw std::string("module config doesn't have 'ipv6DestinationPrefixes'");
	}

	if (removePrefix(*prefixes, prefixRaw))
	{
		saveConfig(root);
	}
}

} /* namespace decap */

namespace nat64stateless
{

static void allowAny(const std::string& module,
                     const std::string& prefixRaw,
                     const std::string& announceRaw)
{
	auto root = loadConfig();

	auto modules = root.find("modules");
	if (modules == root.end())
	{
		throw std::string("config doesn't have 'modules'");
	}

	auto& nat64 = getModule(root, module);
	checkModuleType(nat64, "nat64stateless");

	const auto& [prefixes, inserted] = nat64.emplace("nat64_prefixes", nlohmann::json::array_t{});
	(void)inserted;

	if (allowPrefix(*prefixes, prefixRaw, announceRaw))
	{
		saveConfig(root);
	}
}

static void disallowAny(const std::string& module,
                        const std::string& prefixRaw,
                        const std::string& announceRaw)
{
	auto root = loadConfig();

	auto& nat64 = getModule(root, module);
	checkModuleType(nat64, "nat64stateless");

	auto prefixes = nat64.find("nat64_prefixes");
	if (prefixes == nat64.end())
	{
		throw std::string("module config doesn't have 'nat64_prefixes'");
	}

	if (disallowPrefix(*prefixes, prefixRaw, announceRaw))
	{
		saveConfig(root);
	}
}

static void removeAny(const std::string& module,
                      const std::string& prefixRaw)
{
	auto root = loadConfig();

	auto& nat64 = getModule(root, module);
	checkModuleType(nat64, "nat64stateless");

	auto prefixes = nat64.find("nat64_prefixes");
	if (prefixes == nat64.end())
	{
		throw std::string("module config doesn't have 'nat64_prefixes'");
	}

	if (removePrefix(*prefixes, prefixRaw))
	{
		saveConfig(root);
	}
}

void allow4(const std::string& module,
            const std::string& prefixRaw,
            const std::string& announceRaw)
{
	validateIPv4Prefix(prefixRaw, announceRaw);

	allowAny(module, prefixRaw, announceRaw);
}

void disallow4(const std::string& module,
               const std::string& prefixRaw,
               const std::string& announceRaw)
{
	disallowAny(module, prefixRaw, announceRaw);
}

void remove4(const std::string& module,
             const std::string& prefixRaw)
{
	removeAny(module, prefixRaw);
}

void allow6(const std::string& module,
            const std::string& prefixRaw,
            const std::string& announceRaw)
{
	validateIPv6Prefix(prefixRaw, announceRaw);

	allowAny(module, prefixRaw, announceRaw);
}

void disallow6(const std::string& module,
               const std::string& prefixRaw,
               const std::string& announceRaw)
{
	disallowAny(module, prefixRaw, announceRaw);
}

void remove6(const std::string& module,
             const std::string& prefixRaw)
{
	removeAny(module, prefixRaw);
}

}

void reload()
{
	interface::controlPlane controlPlane{};
	if (auto ec = controlPlane.loadConfig({}); ec != eResult::success)
	{
		std::cerr << "error: " << common::result_to_c_str(ec) << std::endl;
		std::exit(1);
	}
}

} /* namespace config */
