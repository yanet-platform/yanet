#pragma once

#include <rte_config.h>
#include <rte_ip.h>
#include <rte_udp.h>

#include "common/type.h"

#include "common.h"

namespace dataplane
{

struct metadata
{
	tPortId fromPortId;
	uint16_t network_headerType;
	uint16_t network_headerOffset;
	uint16_t network_fragmentHeaderOffset;
	uint8_t network_flags;
	uint8_t transport_headerType;
	uint16_t transport_headerOffset;
	uint16_t transport_flags;
	uint16_t payload_length;
	uint32_t hash;
	uint32_t flowLabel; ///< @todo: union
	uint8_t repeat_ttl;
	uint8_t already_early_decapped;
	tAclId aclId : 16;
	uint32_t vrfId;
	uint32_t in_logicalport_id;
	uint32_t out_logicalport_id;
	common::globalBase::flow_t flow;
};

static_assert(sizeof(metadata) + sizeof(rte_ipv6_hdr) ///< encap
                              + sizeof(rte_ipv6_hdr) + sizeof(rte_udp_hdr) + YADECAP_MPLS_HEADER_SIZE ///< route tunnel
                              + (2 * YADECAP_MPLS_HEADER_SIZE) ///< route
                              + 4 ///< vlan
                              + 8 ///< secret area
                      <= RTE_PKTMBUF_HEADROOM,
              "invalid size of headroom");

}
