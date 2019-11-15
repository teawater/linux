// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/dma-iommu.h>
#include <linux/list.h>
#include <linux/pci.h>
#include <linux/virt_iommu.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_pci.h>
#include <uapi/linux/virtio_iommu.h>

struct viommu_cap_config {
	u8 bar;
	u32 length; /* structure size */
	u32 offset; /* structure offset within the bar */
};

union viommu_topo_cfg {
	__le16					type;
	struct virtio_iommu_topo_pci_range	pci;
	struct virtio_iommu_topo_endpoint	ep;
};

struct viommu_spec {
	struct device				*dev; /* transport device */
	struct fwnode_handle			*fwnode;
	struct iommu_ops			*ops;
	struct list_head			list;
	size_t					num_items;
	/* The config array of length num_items follows */
	union viommu_topo_cfg			cfg[];
};

static LIST_HEAD(viommus);
static DEFINE_MUTEX(viommus_lock);

#define VPCI_FIELD(field) offsetof(struct virtio_pci_cap, field)

static inline int viommu_pci_find_capability(struct pci_dev *dev, u8 cfg_type,
					     struct viommu_cap_config *cap)
{
	int pos;
	u8 bar;

	for (pos = pci_find_capability(dev, PCI_CAP_ID_VNDR);
	     pos > 0;
	     pos = pci_find_next_capability(dev, pos, PCI_CAP_ID_VNDR)) {
		u8 type;

		pci_read_config_byte(dev, pos + VPCI_FIELD(cfg_type), &type);
		if (type != cfg_type)
			continue;

		pci_read_config_byte(dev, pos + VPCI_FIELD(bar), &bar);

		/* Ignore structures with reserved BAR values */
		if (type != VIRTIO_PCI_CAP_PCI_CFG && bar > 0x5)
			continue;

		cap->bar = bar;
		pci_read_config_dword(dev, pos + VPCI_FIELD(length),
				      &cap->length);
		pci_read_config_dword(dev, pos + VPCI_FIELD(offset),
				      &cap->offset);

		return pos;
	}
	return 0;
}

static void viommu_ccopy(__le32 *dst, u32 __iomem *src, size_t length)
{
	size_t i;

	/* For the moment all our config structures align on 32b */
	if (WARN_ON(length % 4))
		return;

	for (i = 0; i < length / 4; i++)
		/* Keep little-endian data */
		dst[i] = cpu_to_le32(ioread32(src + i));
}

static int viommu_parse_topology(struct device *dev,
				 struct virtio_iommu_config __iomem *cfg)
{
	size_t i;
	size_t spec_length;
	struct viommu_spec *viommu_spec;
	u32 offset, item_length, num_items;

	offset = ioread32(&cfg->topo_config.offset);
	item_length = ioread32(&cfg->topo_config.item_length);
	num_items = ioread32(&cfg->topo_config.num_items);
	if (!offset || !num_items || !item_length)
		return 0;

	spec_length = sizeof(*viommu_spec) + num_items *
					     sizeof(union viommu_topo_cfg);
	viommu_spec = kzalloc(spec_length, GFP_KERNEL);
	if (!viommu_spec)
		return -ENOMEM;

	viommu_spec->dev = dev;

	/* Copy in the whole array, sort it out later */
	for (i = 0; i < num_items; i++) {
		size_t read_length = min_t(size_t, item_length,
					   sizeof(union viommu_topo_cfg));

		viommu_ccopy((__le32 *)&viommu_spec->cfg[i],
			     (void __iomem *)cfg + offset,
			     read_length);

		offset += item_length;
	}
	viommu_spec->num_items = num_items;

	mutex_lock(&viommus_lock);
	list_add(&viommu_spec->list, &viommus);
	mutex_unlock(&viommus_lock);

	return 0;
}

static void viommu_pci_parse_topology(struct pci_dev *dev)
{
	int pos;
	u32 features;
	void __iomem *regs;
	struct viommu_cap_config cap = {0};
	struct virtio_pci_common_cfg __iomem *common_cfg;

	/*
	 * The virtio infrastructure might not be loaded at this point. we need
	 * to access the BARs ourselves.
	 */
	pos = viommu_pci_find_capability(dev, VIRTIO_PCI_CAP_COMMON_CFG, &cap);
	if (!pos) {
		pci_warn(dev, "common capability not found\n");
		return;
	}

	if (pci_enable_device_mem(dev))
		return;

	regs = pci_iomap(dev, cap.bar, 0);
	if (!regs)
		return;

	common_cfg = regs + cap.offset;

	/* Find out if the device supports topology description */
	writel(0, &common_cfg->device_feature_select);
	features = ioread32(&common_cfg->device_feature);

	pci_iounmap(dev, regs);

	if (!(features & BIT(VIRTIO_IOMMU_F_TOPOLOGY))) {
		pci_dbg(dev, "device doesn't have topology description");
		return;
	}

	pos = viommu_pci_find_capability(dev, VIRTIO_PCI_CAP_DEVICE_CFG, &cap);
	if (!pos) {
		pci_warn(dev, "device config capability not found\n");
		return;
	}

	regs = pci_iomap(dev, cap.bar, 0);
	if (!regs)
		return;

	pci_info(dev, "parsing virtio-iommu topology\n");
	viommu_parse_topology(&dev->dev, regs + cap.offset);
	pci_iounmap(dev, regs);
}

/*
 * Catch a PCI virtio-iommu implementation early to get the topology description
 * before we start probing other endpoints.
 */
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_REDHAT_QUMRANET, 0x1040 + VIRTIO_ID_IOMMU,
			viommu_pci_parse_topology);

/*
 * Return true if the device matches this topology structure. Write the endpoint
 * ID into epid if it's the case.
 */
static bool viommu_parse_pci(struct pci_dev *pdev, union viommu_topo_cfg *cfg,
			     u32 *epid)
{
	u32 endpoint_start;
	u16 start, end, domain;
	u16 devid = pci_dev_id(pdev);
	u16 type = le16_to_cpu(cfg->type);

	if (type != VIRTIO_IOMMU_TOPO_PCI_RANGE)
		return false;

	start		= le16_to_cpu(cfg->pci.requester_start);
	end		= le16_to_cpu(cfg->pci.requester_end);
	domain		= le16_to_cpu(cfg->pci.hierarchy);
	endpoint_start	= le32_to_cpu(cfg->pci.endpoint_start);

	if (pci_domain_nr(pdev->bus) == domain &&
	    devid >= start && devid <= end) {
		*epid = devid - start + endpoint_start;
		return true;
	}
	return false;
}

static const struct iommu_ops *virt_iommu_setup(struct device *dev)
{
	struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);
	const struct iommu_ops *viommu_ops = NULL;
	struct fwnode_handle *viommu_fwnode;
	struct viommu_spec *viommu_spec;
	struct pci_dev *pci_dev = NULL;
	struct device *viommu_dev;
	bool found = false;
	size_t i;
	u32 epid;
	int ret;

	/* Already translated? */
	if (fwspec && fwspec->ops)
		return NULL;

	if (dev_is_pci(dev)) {
		pci_dev = to_pci_dev(dev);
	} else {
		/* At the moment we don't support platform devices */
		return NULL;
	}

	mutex_lock(&viommus_lock);
	list_for_each_entry(viommu_spec, &viommus, list) {
		for (i = 0; i < viommu_spec->num_items; i++) {
			union viommu_topo_cfg *cfg = &viommu_spec->cfg[i];

			found = viommu_parse_pci(pci_dev, cfg, &epid);
			if (found)
				break;
		}
		if (found) {
			viommu_ops = viommu_spec->ops;
			viommu_fwnode = viommu_spec->fwnode;
			viommu_dev = viommu_spec->dev;
			break;
		}
	}
	mutex_unlock(&viommus_lock);
	if (!found)
		return NULL;

	/* We're not translating ourselves. */
	if (viommu_dev == dev)
		return NULL;

	/*
	 * If we found a PCI range managed by the viommu, we're the ones that
	 * have to request ACS.
	 */
	if (pci_dev)
		pci_request_acs();

	if (!viommu_ops)
		return ERR_PTR(-EPROBE_DEFER);

	ret = iommu_fwspec_init(dev, viommu_fwnode, viommu_ops);
	if (ret)
		return ERR_PTR(ret);

	iommu_fwspec_add_ids(dev, &epid, 1);

	return viommu_ops;
}

/**
 * virt_dma_configure - Configure DMA of virtualized devices
 * @dev: the endpoint
 *
 * Setup the DMA and IOMMU ops of a virtual device, for platforms without DT or
 * ACPI.
 *
 * Return: -EPROBE_DEFER if the device is managed by an IOMMU that hasn't been
 *   probed yet, 0 otherwise
 */
int virt_dma_configure(struct device *dev)
{
	const struct iommu_ops *iommu_ops;

	iommu_ops = virt_iommu_setup(dev);
	if (IS_ERR_OR_NULL(iommu_ops)) {
		int ret = PTR_ERR(iommu_ops);

		if (ret == -EPROBE_DEFER || ret == 0)
			return ret;
		dev_err(dev, "error %d while setting up virt IOMMU\n", ret);
		return 0;
	}

	/*
	 * If we have reason to believe the IOMMU driver missed the initial
	 * add_device callback for dev, replay it to get things in order.
	 */
	if (dev->bus && !device_iommu_mapped(dev))
		iommu_probe_device(dev);

	/* Assume coherent, as well as full 64-bit addresses. */
#ifdef CONFIG_ARCH_HAS_SETUP_DMA_OPS
	arch_setup_dma_ops(dev, 0, ~0ULL, iommu_ops, true);
#else
	iommu_setup_dma_ops(dev, 0, ~0ULL);
#endif
	return 0;
}

/**
 * virt_set_iommu_ops - Set the IOMMU ops of a virtual IOMMU device
 * @dev: the IOMMU device (transport)
 * @ops: the new IOMMU ops or NULL
 *
 * Setup the iommu_ops associated to a viommu_spec, once the driver is loaded
 * and the device probed.
 */
void virt_set_iommu_ops(struct device *dev, struct iommu_ops *ops)
{
	struct viommu_spec *viommu_spec;

	mutex_lock(&viommus_lock);
	list_for_each_entry(viommu_spec, &viommus, list) {
		if (viommu_spec->dev == dev) {
			viommu_spec->ops = ops;
			viommu_spec->fwnode = ops ? dev->fwnode : NULL;
			break;
		}
	}
	mutex_unlock(&viommus_lock);
}
EXPORT_SYMBOL_GPL(virt_set_iommu_ops);
