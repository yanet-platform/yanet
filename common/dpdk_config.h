#ifndef YANET_DPDK_CONFIG_H
#define YANET_DPDK_CONFIG_H

#include <rte_config.h>

#undef RTE_MAX_MEM_MB_PER_LIST
#define RTE_MAX_MEM_MB_PER_LIST 65536

#endif
