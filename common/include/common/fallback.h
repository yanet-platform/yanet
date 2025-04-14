#pragma once

#include <rte_ether.h>
#include <rte_version.h>

#if RTE_VERSION >= RTE_VERSION_NUM(20, 11, 0, 0)

using generic_rte_ether_hdr = rte_ether_hdr;

#else

#define RTE_ETH_RSS_IP ETH_RSS_IP
#define RTE_ETH_RSS_TCP ETH_RSS_TCP
#define RTE_ETH_RSS_UDP ETH_RSS_UDP
#define RTE_ETH_LINK_UP ETH_LINK_UP
#define RTE_ETH_LINK_DOWN ETH_LINK_DOWN
#define RTE_ETH_LINK_FULL_DUPLEX ETH_LINK_FULL_DUPLEX
#define RTE_ETH_LINK_SPEED_100G ETH_LINK_SPEED_100G
#define RTE_ETH_LINK_SPEED_40G ETH_LINK_SPEED_40G
#define RTE_ETH_LINK_SPEED_25G ETH_LINK_SPEED_25G
#define RTE_ETH_LINK_SPEED_10G ETH_LINK_SPEED_10G
#define RTE_ETH_LINK_SPEED_1G ETH_LINK_SPEED_1G
#define RTE_ETH_LINK_SPEED_100M ETH_LINK_SPEED_100M
#define RTE_ETH_LINK_SPEED_100M_HD ETH_LINK_SPEED_100M_HD
#define RTE_ETH_LINK_SPEED_10M ETH_LINK_SPEED_10M
#define RTE_ETH_LINK_SPEED_10M_HD ETH_LINK_SPEED_10M_HD
#define RTE_ETH_SPEED_NUM_10G ETH_SPEED_NUM_10G
#define RTE_ETH_MQ_RX_RSS ETH_MQ_RX_RSS
#define CALL_MAIN CALL_MASTER

struct generic_rte_ether_hdr
{
	struct rte_ether_addr dst_addr; /**< Destination address. */
	struct rte_ether_addr src_addr; /**< Source address. */
	rte_be16_t ether_type; /**< Frame type. */
} __rte_aligned(2);

#endif
