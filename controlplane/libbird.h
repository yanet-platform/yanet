#ifndef LIBBIRD_H
#define LIBBIRD_H

#include <stdint.h>

#define NET_IP4		1
#define NET_IP6		2
#define NET_VPN4	3
#define NET_VPN6	4
#define NET_ROA4	5
#define NET_ROA6	6
#define NET_FLOW4	7
#define NET_FLOW6	8
#define NET_IP6_SADR	9
#define NET_MPLS	10
#define NET_MAX		11

#define NB_IP4		(1 << NET_IP4)
#define NB_IP6		(1 << NET_IP6)
#define NB_VPN4		(1 << NET_VPN4)
#define NB_VPN6		(1 << NET_VPN6)
#define NB_ROA4		(1 << NET_ROA4)
#define NB_ROA6		(1 << NET_ROA6)
#define NB_FLOW4	(1 << NET_FLOW4)
#define NB_FLOW6	(1 << NET_FLOW6)
#define NB_IP6_SADR	(1 << NET_IP6_SADR)
#define NB_MPLS		(1 << NET_MPLS)

#define NB_IP		(NB_IP4 | NB_IP6)
#define NB_VPN		(NB_VPN4 | NB_VPN6)
#define NB_ROA		(NB_ROA4 | NB_ROA6)
#define NB_FLOW		(NB_FLOW4 | NB_FLOW6)
#define NB_DEST		(NB_IP | NB_IP6_SADR | NB_VPN | NB_MPLS)
#define NB_ANY		0xffffffff

#define BA_ORIGIN		0x01	/* RFC 4271 */		/* WM */
#define BA_AS_PATH		0x02				/* WM */
#define BA_NEXT_HOP		0x03				/* WM */
#define BA_MULTI_EXIT_DISC	0x04				/* ON */
#define BA_LOCAL_PREF		0x05				/* WD */
#define BA_ATOMIC_AGGR		0x06				/* WD */
#define BA_AGGREGATOR		0x07				/* OT */
#define BA_COMMUNITY		0x08	/* RFC 1997 */		/* OT */
#define BA_ORIGINATOR_ID	0x09	/* RFC 4456 */		/* ON */
#define BA_CLUSTER_LIST		0x0a	/* RFC 4456 */		/* ON */
#define BA_MP_REACH_NLRI	0x0e	/* RFC 4760 */
#define BA_MP_UNREACH_NLRI	0x0f	/* RFC 4760 */
#define BA_EXT_COMMUNITY	0x10	/* RFC 4360 */
#define BA_AS4_PATH             0x11	/* RFC 6793 */
#define BA_AS4_AGGREGATOR       0x12	/* RFC 6793 */
#define BA_AIGP			0x1a	/* RFC 7311 */
#define BA_LARGE_COMMUNITY	0x20	/* RFC 8092 */
#define BA_ONLY_TO_CUSTOMER	0x23	/* RFC 9234 */

/* Bird's private internal BGP attributes */
#define BA_MPLS_LABEL_STACK	0xfe	/* MPLS label stack transfer attribute */

#define EA_ID(ea) ((ea) & 0xff)
#define EA_PROTO(ea) ((ea) >> 8)

typedef uint32_t ip4_addr;

typedef struct ip6_addr {
  uint32_t addr[4];
} ip6_addr;

typedef ip6_addr ip_addr;

typedef struct net_addr {
  uint8_t type;
  uint8_t pxlen;
  uint16_t length;
  uint8_t data[20];
  uint64_t align[0];
} net_addr;

typedef struct net_addr_ip4 {
  uint8_t type;
  uint8_t pxlen;
  uint16_t length;
  ip4_addr prefix;
} net_addr_ip4;

typedef struct net_addr_ip6 {
  uint8_t type;
  uint8_t pxlen;
  uint16_t length;
  ip6_addr prefix;
} net_addr_ip6;

typedef struct net_addr_vpn4 {
  uint8_t type;
  uint8_t pxlen;
  uint16_t length;
  ip4_addr prefix;
  uint64_t rd;
} net_addr_vpn4;

typedef struct net_addr_vpn6 {
  uint8_t type;
  uint8_t pxlen;
  uint16_t length;
  ip6_addr prefix;
  uint32_t padding;
  uint64_t rd;
} net_addr_vpn6;

typedef struct net_addr_roa4 {
  uint8_t type;
  uint8_t pxlen;
  uint16_t length;
  ip4_addr prefix;
  uint32_t max_pxlen;
  uint32_t asn;
} net_addr_roa4;

typedef struct net_addr_roa6 {
  uint8_t type;
  uint8_t pxlen;
  uint16_t length;
  ip6_addr prefix;
  uint32_t max_pxlen;
  uint32_t asn;
} net_addr_roa6;

typedef struct net_addr_flow4 {
  uint8_t type;
  uint8_t pxlen;
  uint16_t length;
  ip4_addr prefix;
  uint8_t data[0];
} net_addr_flow4;

typedef struct net_addr_flow6 {
  uint8_t type;
  uint8_t pxlen;
  uint16_t length;
  ip6_addr prefix;
  uint8_t data[0];
} net_addr_flow6;

typedef struct net_addr_mpls {
  uint8_t type;
  uint8_t pxlen;
  uint16_t length;
  uint32_t label;
} net_addr_mpls;

typedef struct net_addr_ip6_sadr {
  uint8_t type;
  uint8_t dst_pxlen;
  uint16_t length;
  ip6_addr dst_prefix;
  int32_t src_pxlen; /* s32 to avoid padding */
  ip6_addr src_prefix;
} net_addr_ip6_sadr;

typedef union net_addr_union {
  net_addr n;
  net_addr_ip4 ip4;
  net_addr_ip6 ip6;
  net_addr_vpn4 vpn4;
  net_addr_vpn6 vpn6;
  net_addr_roa4 roa4;
  net_addr_roa6 roa6;
  net_addr_flow4 flow4;
  net_addr_flow6 flow6;
  net_addr_ip6_sadr ip6_sadr;
  net_addr_mpls mpls;
} net_addr_union;

void
read_bird_feed(const char *sock_name, const char *vrf, class rib_t *rib);

#endif
