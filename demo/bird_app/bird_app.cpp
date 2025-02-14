// #include "bird_app.h"
#include "common/define.h"
#include "controlplane/libbird.h"

#include <iostream>
#include <variant>

common::log::LogPriority common::log::logPriority = common::log::TLOG_DEBUG;

std::ostream& operator<<(std::ostream& os, const common::community_t& lc)
{
	os << lc.toString();
	return os;
}

std::ostream& operator<<(std::ostream& os, const common::large_community_t& lc)
{
	os << lc.toString();
	return os;
}

template<typename T>
std::ostream& PrintCollection(std::ostream& os, T& data, char left, char right)
{
	if (data.empty())
	{
		os << "null";
		return os;
	}

	os << left;
	bool first = true;
	for (const auto& value : data)
	{
		if (first)
		{
			first = false;
		}
		else
		{
			os << ", ";
		}
		os << value;
	}
	os << right;

	return os;
}

template<typename T>
std::ostream& operator<<(std::ostream& os, const std::set<T>& data)
{
	return PrintCollection(os, data, '{', '}');
}

template<typename T>
std::ostream& operator<<(std::ostream& os, const std::vector<T>& data)
{
	return PrintCollection(os, data, '[', ']');
}

void PrintRibRequests(common::icp::rib_update::request& requests)
{
	std::cout << "--------------------------------------------\n";
	std::cout << "new requests: " << requests.size() << "\n";
	for (const auto& action : requests)
	{
		if (std::holds_alternative<common::icp::rib_update::insert>(action))
		{
			const auto& [protocol, vrf, priority, insert_data] = std::get<common::icp::rib_update::insert>(action);
			std::cout << "insert, protocol=" << protocol << ", vrf=" << vrf << ", priority=" << priority << "\n";
			for (const auto& [key, tables] : insert_data)
			{
				const auto& [peer, origin, med, aspath, community, large_community, local_preference] = key;
				std::cout << "\tpeer=" << peer.toString() << ", origin=" << origin << ", med=" << med
				          << ", aspath=" << aspath << ", community=" << community
				          << ", large_community=" << large_community << "\n";
				for (const auto& [table_name, nexthops] : tables)
				{
					std::cout << "\t\ttable_name=" << table_name << "\n";
					for (const auto& [nexthop, prefixes] : nexthops)
					{
						std::cout << "\t\t\tnexthop=" << nexthop.toString() << "\n";
						for (const auto& [prefix, path_information, labels] : prefixes)
						{
							std::cout << "\t\t\t\tprefix=" << prefix.toString() << ", path_information="
							          << path_information << ", labels=" << labels << "\n";
						}
					}
				}
			}
		}
		else if (std::holds_alternative<common::icp::rib_update::remove>(action))
		{
			const auto& [protocol, vrf, priority, peers] = std::get<common::icp::rib_update::remove>(action);
			std::cout << "remove, protocol=" << protocol << ", vrf=" << vrf << ", priority=" << priority << "\n";
			for (const auto& [peer, tables] : peers)
			{
				std::cout << "\tpeer=" << peer.toString() << "\n";
				for (const auto& [table_name, prefixes] : tables)
				{
					std::cout << "\t\ttable_name=" << table_name << "\n";
					for (const auto& [prefix, path_information, labels] : prefixes)
					{
						std::cout << "\t\t\tprefix=" << prefix.toString() << ", path_information="
						          << path_information << ", labels=" << labels << "\n";
					}
				}
			}
		}
		else
		{
			std::cout << "bad action type\n";
		}
	}

	requests.clear();
	std::cout.flush();
}

int main(int argc, char** argv)
{
	if (argc != 2)
	{
		std::cout << "Usage: " << argv[0] << " <name_socket_from_bird>\n";
		return 1;
	}

	const char* sock_name = argv[1];
	const char* vrf = "default";
	read_bird_feed(sock_name, vrf, PrintRibRequests);

	return 0;
}
