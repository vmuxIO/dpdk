#include <rte_pci.h>
#include <ethdev_driver.h>
#include <ethdev_pci.h>
#include <bus_pci_driver.h>
#include <rte_io.h>

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

static uint16_t
vdpdk_recv_pkts(void *rx_queue,
	      struct rte_mbuf **rx_pkts,
	      uint16_t nb_pkts);

static uint16_t
vdpdk_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);

enum VDPDK_OFFSET {
	DEBUG_STRING = 0x0,
};

enum VDPDK_CONSTS {
	REGION_SIZE = 0x1000,
	PKT_SIGNAL_OFF = REGION_SIZE - 0x40,
	MAX_PKT_LEN = PKT_SIGNAL_OFF,
	MAX_RX_DESCS = 256,
};

struct vdpdk_private_data {
	unsigned char *signal;
	unsigned char *tx;
	unsigned char *rx;

	struct rte_mempool *rx_pool;
	struct rte_mbuf *rx_bufs[MAX_RX_DESCS];
	unsigned rx_buf_count;
};

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
	// .rx_queue_release             = vdpdk_dev_rx_queue_release,
	.tx_queue_setup               = vdpdk_tx_queue_setup,
	// .tx_queue_release             = vdpdk_dev_tx_queue_release,
	.link_update                  = vdpdk_link_update,
};

static int
vdpdk_dev_configure(struct rte_eth_dev *dev)
{
	return 0;
}

static int
vdpdk_dev_info_get(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{
	dev_info->min_rx_bufsize = 1024;
	dev_info->max_rx_pktlen = 9728;
	dev_info->max_rx_queues = 1;
	dev_info->max_tx_queues = 1;

	dev_info->rx_desc_lim = (struct rte_eth_desc_lim) {
		.nb_max = MAX_RX_DESCS,
		.nb_min = 64,
		.nb_align = 32,
	};

	return 0;
}

static int
vdpdk_dev_start(struct rte_eth_dev *dev)
{
	return 0;
}

static int
vdpdk_dev_set_link_up(struct rte_eth_dev *dev)
{
	return 0;
}

static int
vdpdk_rx_queue_start(struct rte_eth_dev *dev, uint16_t rx_queue_id)
{
	return 0;
}

static int
vdpdk_rx_queue_stop(struct rte_eth_dev *dev, uint16_t rx_queue_id)
{
	return 0;
}

static int
vdpdk_tx_queue_start(struct rte_eth_dev *dev, uint16_t tx_queue_id) {
	return 0;
}

static int
vdpdk_tx_queue_stop(struct rte_eth_dev *dev, uint16_t tx_queue_id) {
	return 0;
}

static int
vdpdk_rx_queue_setup(struct rte_eth_dev *dev,
		   uint16_t queue_idx,
		   uint16_t nb_desc,
		   unsigned int socket_id,
		   const struct rte_eth_rxconf *rx_conf,
		   struct rte_mempool *mp) {
	if (queue_idx != 0) return -EINVAL;
	dev->data->rx_queues[0] = dev->data->dev_private;
	struct vdpdk_private_data *data = dev->data->dev_private;
	data->rx_pool = mp;
	if (nb_desc < 64 || nb_desc > MAX_RX_DESCS) {
		return -EINVAL;
	}
	if (rte_pktmbuf_alloc_bulk(mp, data->rx_bufs, nb_desc) != 0) {
		return -ENOMEM;
	}
	data->rx_buf_count = nb_desc;
	return 0;
}

static int
vdpdk_tx_queue_setup(struct rte_eth_dev *dev,
		   uint16_t queue_idx,
		   uint16_t nb_desc,
		   unsigned int socket_id,
		   const struct rte_eth_txconf *tx_conf) {
	if (queue_idx != 0) return -EINVAL;
	dev->data->tx_queues[0] = dev->data->dev_private;
	return 0;
}

static uint16_t
vdpdk_recv_pkts(void *rx_queue,
	      struct rte_mbuf **rx_pkts,
	      uint16_t nb_pkts) {
	struct vdpdk_private_data *regs = rx_queue;
	uint8_t *lock = regs->rx + PKT_SIGNAL_OFF;

	unsigned char *ptr = regs->rx;
	unsigned char *end = ptr + MAX_PKT_LEN;
	const size_t addr_size = sizeof(uintptr_t);

	if (nb_pkts > regs->rx_buf_count) {
		nb_pkts = regs->rx_buf_count;
	}

	while (rte_read8(lock) != 1);

	for (unsigned i = 0; i < nb_pkts; i++) {
		if (ptr + 2 + addr_size > end) {
			break;
		}

		struct rte_mbuf *buf = regs->rx_bufs[i];

		uint16_t max_len = rte_pktmbuf_tailroom(buf);
		ptr[0] = max_len;
		ptr[1] = max_len >> 8;
		ptr += 2;

		uintptr_t dma_addr = rte_pktmbuf_iova(buf);
		rte_memcpy(ptr, &dma_addr, addr_size);
		ptr += addr_size;
	}

	if (ptr + 2 + addr_size <= end) {
		ptr[0] = 0;
		ptr[1] = 0;
	}

	rte_write8(0, lock);
	while (rte_read8(lock) != 1);

	ptr = regs->rx;
	unsigned i;
	for (i = 0; i < nb_pkts; i++) {
		if (ptr + 2 + addr_size > end) {
			break;
		}

		uint16_t pkt_len = ptr[0] | ((uint16_t)ptr[1] << 8);
		ptr += 2 + addr_size;

		if (pkt_len == 0) {
			break;
		}

		struct rte_mbuf *new_buf = rte_pktmbuf_alloc(regs->rx_pool);
		if (!new_buf) {
			break;
		}

		rx_pkts[i] = regs->rx_bufs[i];
		rx_pkts[i]->data_len = pkt_len;
		rx_pkts[i]->pkt_len = pkt_len;
		rx_pkts[i]->nb_segs = 1;
		rx_pkts[i]->next = NULL;
		regs->rx_bufs[i] = new_buf;
	}

	return i;
}

static uint16_t
vdpdk_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts) {
	struct vdpdk_private_data *regs = tx_queue;
	uint8_t *lock = regs->tx + PKT_SIGNAL_OFF;

	unsigned char *ptr = regs->tx;
	unsigned char *end = ptr + MAX_PKT_LEN;
	const size_t addr_size = sizeof(uintptr_t);

	while (rte_read8(lock) != 1);

	unsigned i;
	for (i = 0; i < nb_pkts; i++) {
		struct rte_mbuf *seg = tx_pkts[i];

		if (ptr + 2 + addr_size > end) {
			break;
		}

		uint16_t pkt_len = seg->pkt_len;

		// TODO:
		if (seg->next != NULL) {
			break;
		}
		// while (seg != NULL) {
		// 	rte_memcpy(data_ptr, rte_pktmbuf_mtod(seg, void *), seg->data_len);
		// 	data_ptr += seg->data_len;
		// 	struct rte_mbuf *next = seg->next;
		// 	rte_pktmbuf_free_seg(seg);
		// 	seg = next;
		// }

		ptr[0] = pkt_len;
		ptr[1] = pkt_len >> 8;
		ptr += 2;

		uintptr_t dma_addr = rte_pktmbuf_iova(seg);
		rte_memcpy(ptr, &dma_addr, addr_size);
		ptr += addr_size;
	}

	// sentinel packet length
	if (ptr + 2 + addr_size <= end) {
		ptr[0] = 0;
		ptr[1] = 0;
	}

	rte_write8(0, lock);

	unsigned success_pkts = i;

	//TODO: for now we wait here until packets were sent so we can clean up
	while (rte_read8(lock) != 1);
	rte_pktmbuf_free_bulk(tx_pkts, success_pkts);

	return success_pkts;
}

static int
vdpdk_link_update(struct rte_eth_dev *dev, int wait_to_complete)
{
	return 0;
}

static int
vdpdk_dev_init(struct rte_eth_dev *dev)
{
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
	// PMD_INIT_LOG(NOTICE, "VDPDK ADDRESS %p", dkaddr);
	char dkbuf[100] = {0};
	uint8_t dku8 = rte_read8(dkaddr);
	memcpy(dkbuf, &dku8, 1);
	// PMD_INIT_LOG(NOTICE, "read8: %x (%s)", dku8, dkbuf);
	uint16_t dku16 = rte_read16(dkaddr);
	memcpy(dkbuf, &dku16, 2);
	// PMD_INIT_LOG(NOTICE, "read16: %x (%s)", dku16, dkbuf);
	uint32_t dku32 = rte_read32(dkaddr);
	memcpy(dkbuf, &dku32, 4);
	// PMD_INIT_LOG(NOTICE, "read32: %x (%s)", dku32, dkbuf);
	uint64_t dku64 = rte_read64(dkaddr);
	memcpy(dkbuf, &dku64, 8);
	// PMD_INIT_LOG(NOTICE, "read64: %lx (%s)", dku64, dkbuf);

	for (size_t i = 0; i < sizeof(dkbuf) - 1; i++) {
		char c = rte_read8((char *)dkaddr + i);
		dkbuf[i] = c;
		if (c == '\0') break;
	}
	// PMD_INIT_LOG(NOTICE, "read string: %s", dkbuf);

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
