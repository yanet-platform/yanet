#pragma once

#include <array>

#include "common/type.h"

#include "common.h"

class cControlPlane;

//

using ipv4_address_t = common::ipv4_address_t;
using ipv6_address_t = common::ipv6_address_t;
using ip_address_t = common::ip_address_t;
using ipv4_prefix_t = common::ipv4_prefix_t;
using ipv4_prefix_with_announces_t = common::ipv4_prefix_with_announces_t;
using ipv6_prefix_t = common::ipv6_prefix_t;
using ipv6_prefix_with_announces_t = common::ipv6_prefix_with_announces_t;
using ip_prefix_with_announces_t = common::ip_prefix_with_announces_t;
using ip_prefix_t = common::ip_prefix_t;
using mac_address_t = common::mac_address_t;
using community_t = common::community_t;

using values_t = common::values_t;
using range_t = common::range_t;
using flags_t = common::flags_t;
using ranges_t = common::ranges_t;

//

class rib_t;

namespace controlplane
{

using vrf_id_t = uint32_t;
using value_id_t = uint32_t;

class base_t;

namespace module
{
	class telegraf;
	class bus;
	class protoBus;
}

}

namespace acl
{
using iface_map_t = common::acl::iface_map_t;
using rule_info_t = std::tuple<uint32_t, ///< rule id
                               std::string, ///< rule gen text
                               std::string>; ///< rule orig text

}
