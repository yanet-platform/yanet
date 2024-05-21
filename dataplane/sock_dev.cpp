#include "sock_dev.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#define ALLOW_INTERNAL_API

#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_version.h>

#if RTE_VERSION >= RTE_VERSION_NUM(20, 11, 0, 0)
#include <bus_pci_driver.h>
#include <ethdev_driver.h>
#else
#include <rte_ethdev_driver.h>
#endif

#include <rte_bus_pci.h>
#include <rte_pci.h>

#define MAX_RX_QUEUES 128
#define MAX_TX_QUEUES 128

#define MAX_PACK_SIZE 16384

struct sock_internals;

struct __attribute__((__packed__)) packHeader
{
	uint32_t data_length;
};

struct sock_queue
{
	struct sock_internals* internals;
	struct rte_mempool* mb_pool;
};

struct sock_internals
{
	struct rte_pci_driver pci_drv;
	struct rte_pci_device pci_dev;
	struct rte_pci_id pci_id;
	struct sockaddr_un sockaddr;
	int fd;
	int conFd;
	int portId;
	struct rte_ether_addr address;
	struct eth_dev_ops dev_ops;
	struct sock_queue rx_queues[MAX_RX_QUEUES];
	rte_eth_stats eth_stats;
};

static int
sock_dev_configure(struct rte_eth_dev* dev __rte_unused)
{
	return 0;
}

static int
sock_dev_info_get(struct rte_eth_dev* dev __rte_unused,
                  struct rte_eth_dev_info* dev_info)
{
	dev_info->max_mac_addrs = 1;
	dev_info->max_rx_pktlen = (uint32_t)-1;
	dev_info->max_rx_queues = MAX_RX_QUEUES;
	dev_info->max_tx_queues = MAX_TX_QUEUES;
	dev_info->min_rx_bufsize = 0;

	/* Let the device pass port configuration */
	dev_info->speed_capa = RTE_ETH_LINK_SPEED_10G;
	dev_info->flow_type_rss_offloads = RTE_ETH_MQ_RX_RSS | RTE_ETH_RSS_IP;

	return 0;
}

#if RTE_VERSION >= RTE_VERSION_NUM(20, 11, 0, 0)
static int
sock_dev_start(struct rte_eth_dev* dev)
{
	dev->data->dev_started = 1;
	dev->data->dev_link.link_status = RTE_ETH_LINK_UP;
	return 0;
}

static int
sock_dev_stop(struct rte_eth_dev* dev)
{
	dev->data->dev_started = 0;
	dev->data->dev_link.link_status = RTE_ETH_LINK_DOWN;
	return 0;
}

static int
sock_dev_close(struct rte_eth_dev* dev)
{
	struct sock_internals* internals =
	        (struct sock_internals*)dev->data->dev_private;

	close(internals->fd);
	unlink(internals->sockaddr.sun_path);
	if (internals)
	{
		rte_free(internals);
	}
	return 0;
}
#else
static int
sock_dev_start(struct rte_eth_dev* dev)
{
	dev->data->dev_link.link_status = RTE_ETH_LINK_UP;
	return 0;
}

static void
sock_dev_stop(struct rte_eth_dev* dev)
{
	dev->data->dev_link.link_status = RTE_ETH_LINK_DOWN;
}

static void
sock_dev_close(struct rte_eth_dev* dev)
{
	struct sock_internals* internals =
	        (struct sock_internals*)dev->data->dev_private;

	close(internals->fd);
	unlink(internals->sockaddr.sun_path);
	rte_free(internals);
}
#endif

static int
sock_dev_rx_queue_setup(struct rte_eth_dev* dev,
                        uint16_t rx_queue_id,
                        uint16_t nb_rx_desc __rte_unused,
                        unsigned int socket_id __rte_unused,
                        const struct rte_eth_rxconf* rx_conf __rte_unused,
                        struct rte_mempool* mb_pool)
{
	struct sock_internals* si = (struct sock_internals*)dev->data->dev_private;
	dev->data->rx_queues[rx_queue_id] = si->rx_queues + rx_queue_id;
	si->rx_queues[rx_queue_id].internals = si;
	si->rx_queues[rx_queue_id].mb_pool = mb_pool;
	return 0;
}

static int
sock_dev_tx_queue_setup(struct rte_eth_dev* dev,
                        uint16_t tx_queue_id,
                        uint16_t nb_tx_desc __rte_unused,
                        unsigned int socket_id __rte_unused,
                        const struct rte_eth_txconf* tx_conf __rte_unused)
{
	dev->data->tx_queues[tx_queue_id] = dev->data->dev_private;
	return 0;
}

#if RTE_VERSION >= RTE_VERSION_NUM(20, 11, 0, 0)
static void
sock_dev_queue_release(struct rte_eth_dev* dev __rte_unused, short unsigned q __rte_unused)
{
	return;
}
#else
static void
sock_dev_queue_release(void* dev __rte_unused)
{
	return;
}
#endif

static int
sock_dev_mtu_set(struct rte_eth_dev* dev __rte_unused,
                 uint16_t mtu __rte_unused)
{
	return 0;
}

static int
sock_dev_promiscuous_enable(struct rte_eth_dev* dev __rte_unused)
{
	return 0;
}

static int
sock_dev_promiscuous_disable(struct rte_eth_dev* dev __rte_unused)
{
	return 0;
}

static int
sock_dev_allmulticast_enable(struct rte_eth_dev* dev __rte_unused)
{
	return 0;
}

static int
sock_dev_allmulticast_disable(struct rte_eth_dev* dev __rte_unused)
{
	return 0;
}

static int
sock_dev_link_update(struct rte_eth_dev* dev __rte_unused,
                     int wait_to_complete __rte_unused)
{
	return 0;
}

ssize_t readCount(int fd, char* buf, size_t count)
{
	ssize_t pos = read(fd, buf, count);
	if (pos < 0)
	{
		if (errno != EAGAIN && errno != EWOULDBLOCK)
		{
			return -1;
		}
		return 0;
	}
	if (pos == 0)
	{
		return -1; /// EOF
	}

	while (pos < (ssize_t)count)
	{
		ssize_t readen = read(fd, buf + pos, count - pos);
		if (readen > 0)
		{
			pos += readen;
			continue;
		}
		if (readen == 0)
		{
			return -1; /// EOF
		}
		if (errno != EAGAIN && errno != EWOULDBLOCK)
		{
			return -1;
		}
	}
	return count;
}

static uint16_t
sock_dev_rx(void* q, struct rte_mbuf** bufs, uint16_t nb_bufs)
{
	if (nb_bufs == 0)
	{
		return 0;
	}

	struct sock_queue* sq = (struct sock_queue*)q;

	if (sq->internals->conFd < 0)
	{
		sq->internals->conFd = accept4(sq->internals->fd, NULL, NULL, SOCK_NONBLOCK);
	}

	if (sq->internals->conFd < 0)
	{
		return 0; /// No connection
	}

	struct packHeader hdr;
	char read_buf[MAX_PACK_SIZE];

	ssize_t rc = readCount(sq->internals->conFd, (char*)&hdr, sizeof(hdr));
	if (rc < 0)
	{
		sq->internals->conFd = -1; /// Reset the connection
		return 0;
	}
	if (rc == 0)
	{
		return 0;
	}

	hdr.data_length = ntohl(hdr.data_length);

	/// Packet header received, read the packet until reading is done or an error happened
	do
	{
		rc = readCount(sq->internals->conFd, read_buf, hdr.data_length);
		if (rc < 0)
		{
			sq->internals->eth_stats.ierrors++;
			sq->internals->conFd = -1; /// Reset the connection
			return 0;
		}
	} while (rc == 0); /// Repeat if there is no data yet

	struct rte_mbuf* mbuf;
	mbuf = rte_pktmbuf_alloc(sq->mb_pool);
	if (unlikely(mbuf == NULL))
	{
		sq->internals->eth_stats.ierrors++;
		return 0;
	}

	if (hdr.data_length <= rte_pktmbuf_tailroom(mbuf))
	{
		rte_memcpy(rte_pktmbuf_mtod(mbuf, void*), read_buf, hdr.data_length);
		mbuf->data_len = hdr.data_length;
		mbuf->pkt_len = mbuf->data_len;
		mbuf->port = sq->internals->portId;
		*bufs = mbuf;

		sq->internals->eth_stats.ipackets++;
		sq->internals->eth_stats.ibytes += hdr.data_length;
	}
	else /// Packet does not fit, drop it
	{
		sq->internals->eth_stats.ierrors++;
		rte_pktmbuf_free(mbuf);
		return 0;
	}
	return 1;
}

static int
writeIovCount(int fd, struct iovec* iov, size_t count)
{
	while (count > 0)
	{
		ssize_t written = writev(fd, iov, count);
		if (written < 0)
		{
			if (errno != EAGAIN && errno != EWOULDBLOCK)
			{
				return -1;
			}
			continue;
		}
		/// Adjust iov
		while (written > 0)
		{
			if (iov->iov_len <= (size_t)written) /// Vec was consumed
			{
				written -= iov->iov_len;
				++iov;
				--count;
				continue;
			}
			iov->iov_base = (void*)((intptr_t)iov->iov_base + written);
			iov->iov_len -= written;
			written = 0;
		}
	}
	return 1;
}

static uint16_t
sock_dev_tx(void* q, struct rte_mbuf** bufs, uint16_t nb_bufs)
{
	if (nb_bufs == 0)
	{
		return 0;
	}

	struct sock_internals* si = (struct sock_internals*)q;
	if (si->conFd < 0)
	{
		si->eth_stats.oerrors++;
		return 0;
	}

	char writeBuf[MAX_PACK_SIZE];

	for (uint16_t i = 0; i < nb_bufs; ++i)
	{
		struct rte_mbuf* mbuf = bufs[i];
		size_t len = rte_pktmbuf_pkt_len(mbuf);

		struct packHeader hdr;
		hdr.data_length = htonl(len);

		struct iovec iov[2];
		iov[0].iov_base = &hdr;
		iov[0].iov_len = sizeof(hdr);

		iov[1].iov_base = (void*)rte_pktmbuf_read(mbuf, 0, len, writeBuf);
		iov[1].iov_len = len;

		if (writeIovCount(si->conFd, iov, 2) < 0)
		{
			si->conFd = -1; /// Reset the connection
			return i;
		}

		si->eth_stats.opackets++;
		si->eth_stats.obytes += len;

		rte_pktmbuf_free(mbuf);
	}
	return nb_bufs;
}

int sock_dev_stats_get(struct rte_eth_dev* dev,
                       struct rte_eth_stats* igb_stats)
{
	sock_internals* private_data = (struct sock_internals*)dev->data->dev_private;
	memcpy(igb_stats, &private_data->eth_stats, sizeof(rte_eth_stats));
	return 0;
}

int sock_dev_create(const char* path, const char* name, uint8_t numa_node)
{
	struct sock_internals* internals = (struct sock_internals*)
	        rte_zmalloc_socket(path, sizeof(struct sock_internals), 0, numa_node);
	if (internals == NULL)
		return ENOSPC;

	internals->pci_id.device_id = 0xBEEF;

	internals->pci_drv.driver.name = "sock_dev";
	internals->pci_drv.id_table = &internals->pci_id;

	internals->pci_dev.device.numa_node = numa_node;
	internals->pci_dev.device.name = internals->sockaddr.sun_path;
	internals->pci_dev.device.driver = &internals->pci_drv.driver;

	internals->dev_ops.dev_configure = sock_dev_configure;
	internals->dev_ops.dev_start = sock_dev_start;
	internals->dev_ops.dev_stop = sock_dev_stop;
	internals->dev_ops.dev_close = sock_dev_close;
	internals->dev_ops.mtu_set = sock_dev_mtu_set;
	internals->dev_ops.dev_infos_get = sock_dev_info_get;
	internals->dev_ops.rx_queue_setup = sock_dev_rx_queue_setup;
	internals->dev_ops.tx_queue_setup = sock_dev_tx_queue_setup;
	internals->dev_ops.rx_queue_release = sock_dev_queue_release;
	internals->dev_ops.tx_queue_release = sock_dev_queue_release;
	internals->dev_ops.link_update = sock_dev_link_update;
	internals->dev_ops.promiscuous_enable = sock_dev_promiscuous_enable;
	internals->dev_ops.promiscuous_disable = sock_dev_promiscuous_disable;
	internals->dev_ops.allmulticast_enable = sock_dev_allmulticast_enable;
	internals->dev_ops.allmulticast_disable = sock_dev_allmulticast_disable;
	internals->dev_ops.stats_get = sock_dev_stats_get;

	unlink(path);
	internals->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
	internals->sockaddr.sun_family = AF_UNIX;
	strncpy(internals->sockaddr.sun_path, path, sizeof(internals->sockaddr.sun_path) - 1);
	bind(internals->fd, (struct sockaddr*)&internals->sockaddr, sizeof(internals->sockaddr));
	listen(internals->fd, 1);
	internals->conFd = -1;

	struct rte_eth_dev* eth_dev = NULL;
	eth_dev = rte_eth_dev_allocate(name);
	if (eth_dev == NULL)
	{
		close(internals->fd);
		unlink(internals->sockaddr.sun_path);
		rte_free(internals);
		return ENOSPC;
	}

	eth_dev->device = &internals->pci_dev.device;

	struct rte_eth_dev_data* data = eth_dev->data;
	data->dev_private = internals;
	data->nb_rx_queues = 0;
	data->nb_tx_queues = 0;
	data->dev_link.link_speed = RTE_ETH_SPEED_NUM_10G;
	data->dev_link.link_duplex = RTE_ETH_LINK_FULL_DUPLEX;
	data->dev_link.link_status = RTE_ETH_LINK_DOWN;
	data->mac_addrs = &internals->address;
	data->promiscuous = 1;
	data->all_multicast = 1;
	data->dev_started = 0;

	eth_dev->dev_ops = &internals->dev_ops;
#if RTE_VERSION < RTE_VERSION_NUM(20, 11, 0, 0)
	data->kdrv = RTE_KDRV_NONE;
#endif
	data->numa_node = numa_node;

	/* finally assign rx and tx ops */
	eth_dev->rx_pkt_burst = sock_dev_rx;
	eth_dev->tx_pkt_burst = sock_dev_tx;

	internals->portId = data->port_id;

	rte_eth_dev_probing_finish(eth_dev);

	return data->port_id;
}
