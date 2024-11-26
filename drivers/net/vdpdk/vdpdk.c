#include <rte_pci.h>
#include <ethdev_driver.h>
#include <ethdev_pci.h>
#include <bus_pci_driver.h>
#include <rte_common.h>
#include <rte_io.h>
#include <rte_log.h>

// TODO: remove
#include <assert.h>

extern int vdpdk_log;

#define VDPDK_LOG(level, fmt, ...) rte_log(RTE_LOG_##level, vdpdk_log, "%s(): " fmt "\n", __func__, ## __VA_ARGS__)
#define VDPDK_TRACE(...) VDPDK_LOG(DEBUG, __VA_ARGS__)

static int vdpdk_dev_configure(struct rte_eth_dev *dev);
static int vdpdk_dev_start(struct rte_eth_dev *dev);
static int vdpdk_dev_info_get(struct rte_eth_dev *dev,
			    struct rte_eth_dev_info *dev_info);

static int vdpdk_dev_set_link_up(struct rte_eth_dev *dev);
static int vdpdk_link_update(struct rte_eth_dev *dev,
			   int wait_to_complete);

static int
vdpdk_rx_queue_setup(struct rte_eth_dev *dev,
		   uint16_t queue_idx,
		   uint16_t nb_desc,
		   unsigned int socket_id,
		   const struct rte_eth_rxconf *rx_conf,
		   struct rte_mempool *mp);

static int
vdpdk_tx_queue_setup(struct rte_eth_dev *dev,
		   uint16_t queue_idx,
		   uint16_t nb_desc,
		   unsigned int socket_id,
		   const struct rte_eth_txconf *tx_conf);

static int vdpdk_tx_queue_start(struct rte_eth_dev *dev, uint16_t tx_queue_id);
static int vdpdk_tx_queue_stop(struct rte_eth_dev *dev, uint16_t tx_queue_id);
static int vdpdk_rx_queue_start(struct rte_eth_dev *dev, uint16_t rx_queue_id);
static int vdpdk_rx_queue_stop(struct rte_eth_dev *dev, uint16_t rx_queue_id);

static void vdpdk_rx_queue_release(struct rte_eth_dev *dev, uint16_t rx_queue_id);
static void vdpdk_tx_queue_release(struct rte_eth_dev *dev, uint16_t tx_queue_id);

static uint16_t
vdpdk_recv_pkts(void *rx_queue,
	      struct rte_mbuf **rx_pkts,
	      uint16_t nb_pkts);

static uint16_t
vdpdk_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);

enum VDPDK_OFFSET {
	DEBUG_STRING = 0x0,
	TX_QUEUE_START = 0x40,
	TX_QUEUE_STOP = 0x80,

	RX_QUEUE_START = 0x140,
	RX_QUEUE_STOP = 0x180,
};

enum VDPDK_CONSTS {
	REGION_SIZE = 0x1000,
	PKT_SIGNAL_OFF = REGION_SIZE - 0x40,
	MAX_PKT_LEN = PKT_SIGNAL_OFF,
	MAX_RX_DESCS = 256,

	TX_DESC_SIZE = 0x20,
	TX_FLAG_AVAIL = 1,

	RX_DESC_SIZE = 0x20,
	RX_FLAG_AVAIL = 1,

	DEFAULT_TX_FREE_THRESH = 32,
};

struct vdpdk_private_data {
	unsigned char *signal;
	unsigned char *tx;
	unsigned char *rx;
};

struct vdpdk_tx_queue {
	struct vdpdk_private_data *private_data;
	const struct rte_memzone *ring;

	uint16_t idx_mask;
	uint16_t idx;

	// Number of descriptors with an associated allocated buffer
	uint32_t alloc_descs;

	// DPDK TX configuration
	uint16_t tx_free_thresh;
};

struct vdpdk_tx_desc {
	union {
		uintptr_t dma_addr;
		uint64_t _pad;
	};
	uint16_t len;
	uint16_t flags;
	struct rte_mbuf *buf;
};
static_assert(sizeof(struct vdpdk_tx_desc) <= TX_DESC_SIZE, "vdpdk tx descriptor: invalid size");
static_assert(offsetof(struct vdpdk_tx_desc, dma_addr) == 0, "vdpdk tx descriptor: unexpected offset");
static_assert(offsetof(struct vdpdk_tx_desc, len) == 8, "vdpdk tx descriptor: unexpected offset");
static_assert(offsetof(struct vdpdk_tx_desc, flags) == 10, "vdpdk tx descriptor: unexpected offset");

struct vdpdk_rx_queue {
	struct vdpdk_private_data *private_data;
	const struct rte_memzone *ring;

	uint16_t idx_mask;
	uint16_t front_idx, back_idx;

	struct rte_mempool *pool;
};

struct vdpdk_rx_desc {
	union {
		uintptr_t dma_addr;
		uint64_t _pad;
	};
	uint16_t len;
	uint16_t flags;
	struct rte_mbuf *buf;
};
static_assert(sizeof(struct vdpdk_rx_desc) <= RX_DESC_SIZE, "vdpdk rx descriptor: invalid size");
static_assert(offsetof(struct vdpdk_rx_desc, dma_addr) == 0, "vdpdk rx descriptor: unexpected offset");
static_assert(offsetof(struct vdpdk_rx_desc, len) == 8, "vdpdk rx descriptor: unexpected offset");
static_assert(offsetof(struct vdpdk_rx_desc, flags) == 10, "vdpdk rx descriptor: unexpected offset");

static const struct rte_pci_id pci_id_vdpdk_map[] = {
	{ RTE_PCI_DEVICE(0x1af4, 0x7abc) },
	{ .vendor_id = 0, /* sentinel */ },
};

static const struct eth_dev_ops vdpdk_eth_dev_ops = {
	.dev_configure                = vdpdk_dev_configure,
	.dev_infos_get                = vdpdk_dev_info_get,
	.dev_start                    = vdpdk_dev_start,
	.dev_set_link_up              = vdpdk_dev_set_link_up,
	.rx_queue_start               = vdpdk_rx_queue_start,
	.rx_queue_stop                = vdpdk_rx_queue_stop,
	.tx_queue_start               = vdpdk_tx_queue_start,
	.tx_queue_stop                = vdpdk_tx_queue_stop,
	.rx_queue_setup               = vdpdk_rx_queue_setup,
	.rx_queue_release             = vdpdk_rx_queue_release,
	.tx_queue_setup               = vdpdk_tx_queue_setup,
	.tx_queue_release             = vdpdk_tx_queue_release,
	.link_update                  = vdpdk_link_update,
};

static int
vdpdk_dev_configure(struct rte_eth_dev *dev)
{
	VDPDK_TRACE();
	return 0;
}

static int
vdpdk_dev_info_get(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{
	VDPDK_TRACE();
	dev_info->min_rx_bufsize = 1024;
	dev_info->max_rx_pktlen = 9728;
	dev_info->max_rx_queues = 1;
	dev_info->max_tx_queues = 1;

	dev_info->rx_desc_lim = (struct rte_eth_desc_lim) {
		.nb_max = MAX_RX_DESCS,
		.nb_min = 64,
		.nb_align = 32,
	};

	dev_info->default_txconf = (struct rte_eth_txconf) {
		.tx_free_thresh = DEFAULT_TX_FREE_THRESH,
	};

	return 0;
}

static int
vdpdk_dev_start(struct rte_eth_dev *dev)
{
	VDPDK_TRACE();
	return 0;
}

static int
vdpdk_dev_set_link_up(struct rte_eth_dev *dev)
{
	VDPDK_TRACE();
	return 0;
}

static int
vdpdk_rx_queue_start(struct rte_eth_dev *dev, uint16_t rx_queue_id)
{
	VDPDK_TRACE("queue: %d", (int)rx_queue_id);
	return 0;
}

static int
vdpdk_rx_queue_stop(struct rte_eth_dev *dev, uint16_t rx_queue_id)
{
	VDPDK_TRACE("queue: %d", (int)rx_queue_id);
	return 0;
}

static int
vdpdk_tx_queue_start(struct rte_eth_dev *dev, uint16_t tx_queue_id) {
	VDPDK_TRACE("queue: %d", (int)tx_queue_id);
	return 0;
}

static int
vdpdk_tx_queue_stop(struct rte_eth_dev *dev, uint16_t tx_queue_id) {
	VDPDK_TRACE("queue: %d", (int)tx_queue_id);
	return 0;
}

static int
vdpdk_rx_queue_setup(struct rte_eth_dev *dev,
		   uint16_t queue_idx,
		   uint16_t nb_desc,
		   unsigned int socket_id,
		   const struct rte_eth_rxconf *rx_conf,
		   struct rte_mempool *mp) {
	VDPDK_TRACE("queue: %d, nb_desc: %d", (int)queue_idx, (int)nb_desc);
	if (queue_idx != 0) return -EINVAL;

	// Free previous queue data
	if (dev->data->rx_queues[queue_idx]) {
		vdpdk_rx_queue_release(dev, queue_idx);
	}

	// Allocate private queue data
	struct vdpdk_rx_queue *rxq = rte_zmalloc_socket("VDPDK_RX_QUEUE", sizeof(*rxq), 0, socket_id);
	if (!rxq) {
		VDPDK_LOG(ERR, "Failed to allocate memory for rx queue data");
		return -ENOMEM;
	}

	// Allocate DMA ring
	size_t ring_elements = rte_align32pow2(nb_desc);
	size_t ring_size = RX_DESC_SIZE * ring_elements;
	const struct rte_memzone *ring = rte_eth_dma_zone_reserve(dev, "rx_ring",
	                                                          queue_idx, ring_size,
	                                                        RTE_CACHE_LINE_SIZE, socket_id);
	if (!ring) {
		rte_free(rxq);
		VDPDK_LOG(ERR,
		          "Failed to allocate DMA memory for RX ring "
		          "(nb_desc = 0x%x, ring_elements = 0x%zx, size = 0x%zx)",
		          (unsigned)nb_desc, ring_elements, ring_size);
		return -ENOMEM;
	}
	memset(ring->addr, 0, ring_size);

	// Allocate mbufs
	struct rte_mbuf **tmp = rte_malloc_socket(NULL, sizeof(*tmp) * nb_desc, __alignof__(*tmp), socket_id);
	if (!tmp) {
		rte_free(rxq);
		rte_eth_dma_zone_free(dev, "rx_ring", queue_idx);
		VDPDK_LOG(ERR, "Failed to allocate memory buffers");
		return -ENOMEM;
	}
	if (rte_pktmbuf_alloc_bulk(mp, tmp, nb_desc) != 0) {
		rte_free(tmp);
		rte_free(rxq);
		rte_eth_dma_zone_free(dev, "rx_ring", queue_idx);
		VDPDK_LOG(ERR, "Failed to allocate memory buffers");
		return -ENOMEM;
	}
	for (size_t i = 0; i < nb_desc; i++) {
		struct vdpdk_rx_desc *desc = (struct vdpdk_rx_desc *)((char *)ring->addr + i * RX_DESC_SIZE);
		desc->buf = tmp[i];
		desc->dma_addr = rte_pktmbuf_iova(desc->buf);
		desc->len = rte_pktmbuf_tailroom(desc->buf);
		desc->flags = RX_FLAG_AVAIL;
	}
	rte_free(tmp);

	// Set queue data
	rxq->private_data = dev->data->dev_private;
	rxq->ring = ring;
	rxq->front_idx = 0;
	rxq->back_idx = nb_desc;
	rxq->idx_mask = ring_elements - 1;
	rxq->pool = mp;

	dev->data->rx_queues[queue_idx] = rxq;

	// Signal queue creation
	rte_write64_relaxed(ring->iova, rxq->private_data->rx);
	rte_write16_relaxed(rxq->idx_mask, rxq->private_data->rx + 8);
	rte_write16(queue_idx, rxq->private_data->signal + RX_QUEUE_START);

	return 0;
}

static int
vdpdk_tx_queue_setup(struct rte_eth_dev *dev,
		   uint16_t queue_idx,
		   uint16_t nb_desc,
		   unsigned int socket_id,
		   const struct rte_eth_txconf *tx_conf) {
	VDPDK_TRACE("queue: %d, nb_desc: %d", (int)queue_idx, (int)nb_desc);
	if (queue_idx != 0) return -EINVAL;

	// Free previous queue
	if (dev->data->tx_queues[queue_idx]) {
		vdpdk_tx_queue_release(dev, queue_idx);
	}

	// Allocate private queue data
	struct vdpdk_tx_queue *txq = rte_zmalloc_socket("VDPDK_TX_QUEUE", sizeof(*txq), 0, socket_id);
	if (!txq) {
		VDPDK_LOG(ERR, "Failed to allocate memory for tx queue data");
		return -ENOMEM;
	}

	// Allocate DMA ring
	size_t ring_elements = rte_align32pow2(nb_desc);
	size_t ring_size = TX_DESC_SIZE * ring_elements;
	const struct rte_memzone *ring = rte_eth_dma_zone_reserve(dev, "tx_ring",
	                                                    queue_idx, ring_size,
	                                                    RTE_CACHE_LINE_SIZE, socket_id);
	if (!ring) {
		rte_free(txq);
		VDPDK_LOG(ERR,
		          "Failed to allocate DMA memory for TX ring "
		          "(nb_desc = 0x%x, ring_elements = 0x%zx, size = 0x%zx)",
		          (unsigned)nb_desc, ring_elements, ring_size);
		return -ENOMEM;
	}
	memset(ring->addr, 0, ring_size);

	// Set queue data
	txq->private_data = dev->data->dev_private;
	txq->ring = ring;
	txq->idx = 0;
	txq->idx_mask = ring_elements - 1;

	txq->alloc_descs = 0;
	txq->tx_free_thresh = tx_conf->tx_free_thresh ? tx_conf->tx_free_thresh : DEFAULT_TX_FREE_THRESH;

	VDPDK_TRACE("queue: %d, tx_free_thresh: %d", (int)queue_idx, (int)tx_conf->tx_free_thresh);

	dev->data->tx_queues[queue_idx] = txq;

	// Signal queue creation
	rte_write64_relaxed(ring->iova, txq->private_data->tx);
	rte_write16_relaxed(txq->idx_mask, txq->private_data->tx + 8);
	rte_write16(queue_idx, txq->private_data->signal + TX_QUEUE_START);

	return 0;
}

static void
vdpdk_rx_queue_release(struct rte_eth_dev *dev, uint16_t rx_queue_id) {
	VDPDK_TRACE("queue: %d", (int)rx_queue_id);

	struct vdpdk_rx_queue *rxq = dev->data->rx_queues[rx_queue_id];
	if (!rxq) {
		return;
	}

	rte_write16(rx_queue_id, rxq->private_data->signal + RX_QUEUE_STOP);

	if (rxq->ring) {
		rte_eth_dma_zone_free(dev, "rx_ring", rx_queue_id);
		rxq->ring = NULL;
	}

	rte_free(rxq);
	dev->data->rx_queues[rx_queue_id] = NULL;
}

static void
vdpdk_tx_queue_release(struct rte_eth_dev *dev, uint16_t tx_queue_id) {
	VDPDK_TRACE("queue: %d", (int)tx_queue_id);

	struct vdpdk_tx_queue *txq = dev->data->tx_queues[tx_queue_id];
	if (!txq) {
		return;
	}

	rte_write16(tx_queue_id, txq->private_data->signal + TX_QUEUE_STOP);

	if (txq->ring) {
		rte_eth_dma_zone_free(dev, "tx_ring", tx_queue_id);
		txq->ring = NULL;
	}

	rte_free(txq);
	dev->data->tx_queues[tx_queue_id] = NULL;
}

static uint16_t
vdpdk_recv_pkts(void *rx_queue,
	      struct rte_mbuf **rx_pkts,
	      uint16_t nb_pkts) {
	struct vdpdk_rx_queue *rxq = rx_queue;
	unsigned char *ring = rxq->ring->addr;

	unsigned i;
	for (i = 0; i < nb_pkts; i++) {
		struct vdpdk_rx_desc *desc = (struct vdpdk_rx_desc *)(ring + (size_t)(rxq->front_idx & rxq->idx_mask) * RX_DESC_SIZE);
		uint16_t flags = rte_read16(&desc->flags);

		// If FLAG_AVAIL is set, buffer has not been filled by vmux yet
		// and no more packets are available to be received
		if (flags & RX_FLAG_AVAIL) {
			break;
		}

		// Ensure we can allocate a new buffer before modifying the ring
		struct rte_mbuf *new_buf = rte_pktmbuf_alloc(rxq->pool);
		if (!new_buf) {
			break;
		}

		// FLAG_AVAIL is not set, therefore vdpdk owns the descriptor

		// Update buffer and return it to caller
		struct rte_mbuf *buf = desc->buf;
		buf->data_len = desc->len;
		buf->pkt_len = desc->len;
		buf->nb_segs = 1;
		buf->next = NULL;
		rx_pkts[i] = buf;
		desc->buf = NULL;

		// Go to next descriptor
		rxq->front_idx++;

		// Enqueue new buffer at the back of queue
		// The descriptor pointed to by back_idx should always be free,
		// because at this point there is always at least one free descriptor
		struct vdpdk_rx_desc *new_desc = (struct vdpdk_rx_desc *)(ring + (size_t)(rxq->back_idx & rxq->idx_mask) * RX_DESC_SIZE);

		// TODO: remove assertion
		assert(!(new_desc->flags & RX_FLAG_AVAIL) && new_desc->buf == NULL);

		new_desc->buf = new_buf;
		new_desc->dma_addr = rte_pktmbuf_iova(new_buf);
		new_desc->len = rte_pktmbuf_tailroom(new_buf);
		flags = RX_FLAG_AVAIL;
		rte_write16(flags, &new_desc->flags);

		rxq->back_idx++;
	}

	return i;
}

static uint16_t
vdpdk_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts) {
	struct vdpdk_tx_queue *txq = tx_queue;
	unsigned char *ring = txq->ring->addr;

	unsigned i;
	for (i = 0; i < nb_pkts; i++) {
		struct rte_mbuf *seg = tx_pkts[i];

		// TODO:
		if (seg->next != NULL) {
			break;
		}

		struct vdpdk_tx_desc *desc = (struct vdpdk_tx_desc *)(ring + (size_t)(txq->idx & txq->idx_mask) * TX_DESC_SIZE);
		uint16_t flags = rte_read16(&desc->flags);

		// If FLAG_AVAIL is set, all descriptors are filled
		if (flags & TX_FLAG_AVAIL) {
			break;
		}

		// FLAG_AVAIL is not set, therefore vdpdk owns the descriptor

		// Free descriptor
		if (desc->buf) {
			rte_pktmbuf_free(desc->buf);
			desc->buf = NULL;
			txq->alloc_descs--;
		}

		// Fill with data
		desc->buf = seg;
		desc->dma_addr = rte_pktmbuf_iova(seg);
		desc->len = seg->data_len;
		txq->alloc_descs++;

		// Set FLAG_AVAIL to give buffer to vmux
		flags |= TX_FLAG_AVAIL;
		rte_write16(flags, &desc->flags);

		// Go to next descriptor
		txq->idx++;
	}

	// Clean ring if alloced buffers exceeds threshold
	if (txq->alloc_descs >= txq->tx_free_thresh) {
		// Our ring should look like this:
		// * group of free descriptors
		// * group of descriptors with allocated mbuf
		// * group of descriptors in use by vmux
		// txq->idx points to the descriptor right after that

		// We scan backwards for free-able descriptors
		uint16_t clean_idx = txq->idx - 1;
		// If we walked backwards through the whole ring, we are definitely done
		uint16_t end_idx = txq->idx - txq->idx_mask - 1;

		// First, we skip the group of descriptors in use by vmux
		for (; clean_idx != end_idx; clean_idx--) {
			struct vdpdk_tx_desc *desc = (struct vdpdk_tx_desc *)(ring + (size_t)(clean_idx & txq->idx_mask) * TX_DESC_SIZE);
			uint16_t flags = rte_read16(&desc->flags);
			if (!(flags & TX_FLAG_AVAIL)) {
				break;
			}
		}

		// Now, clean_idx is either end_idx, or points to a descriptor we own
		// Free buffers until we find a descriptor that was already freed
		for (; clean_idx != end_idx; clean_idx--) {
			struct vdpdk_tx_desc *desc = (struct vdpdk_tx_desc *)(ring + (size_t)(clean_idx & txq->idx_mask) * TX_DESC_SIZE);

			// TODO: remove
			assert(desc->flags == 0);

			if (!desc->buf) {
				break;
			}

			rte_pktmbuf_free(desc->buf);
			desc->buf = NULL;
			txq->alloc_descs--;
		}
	}

	return i;
}

static int
vdpdk_link_update(struct rte_eth_dev *dev, int wait_to_complete)
{
	VDPDK_TRACE();
	return 0;
}

static int
vdpdk_dev_init(struct rte_eth_dev *dev)
{
	VDPDK_TRACE();
	struct rte_pci_device *pci_dev = RTE_DEV_TO_PCI(dev->device);
	dev->dev_ops = &vdpdk_eth_dev_ops;
	// dev->rx_queue_count = ice_rx_queue_count;
	// dev->rx_descriptor_status = ice_rx_descriptor_status;
	// dev->tx_descriptor_status = ice_tx_descriptor_status;
	dev->rx_pkt_burst = vdpdk_recv_pkts;
	dev->tx_pkt_burst = vdpdk_xmit_pkts;
	// dev->tx_pkt_prepare = ice_prep_pkts;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		return -ENOTSUP;
	}

	void *dkaddr = pci_dev->mem_resource[0].addr;
	char dkbuf[100] = {0};

	for (size_t i = 0; i < sizeof(dkbuf) - 1; i++) {
		char c = rte_read8((char *)dkaddr + i);
		dkbuf[i] = c;
		if (c == '\0') break;
	}
	VDPDK_TRACE("debug string: %s", dkbuf);

	strcpy(dkbuf, "Greetings from dpdk");
	for (size_t i = 0; i < sizeof(dkbuf); i++) {
		char c = dkbuf[i];
		rte_write8(c, (char *)dkaddr + DEBUG_STRING);
		if (c == '\0') break;
	}

	struct vdpdk_private_data *regs = dev->data->dev_private;
	regs->signal = pci_dev->mem_resource[0].addr;
	regs->tx = pci_dev->mem_resource[1].addr;
	regs->rx = pci_dev->mem_resource[2].addr;

	return 0;
}

static int
vdpdk_dev_uninit(struct rte_eth_dev *dev)
{
	VDPDK_TRACE();
	(void)dev;

	return 0;
}

static int
vdpdk_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
	      struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_probe(pci_dev,
					     sizeof(struct vdpdk_private_data),
					     vdpdk_dev_init);
}

static int
vdpdk_pci_remove(struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_remove(pci_dev, vdpdk_dev_uninit);
}

static struct rte_pci_driver rte_vdpdk_pmd = {
	.id_table = pci_id_vdpdk_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
	.probe = vdpdk_pci_probe,
	.remove = vdpdk_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_vdpdk, rte_vdpdk_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_vdpdk, pci_id_vdpdk_map);
RTE_PMD_REGISTER_KMOD_DEP(net_vdpdk, "* igb_uio | uio_pci_generic | vfio-pci");
RTE_LOG_REGISTER_DEFAULT(vdpdk_log, NOTICE);
