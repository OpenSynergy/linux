// SPDX-License-Identifier: GPL-2.0+
/* Driver for virtio video device.
 *
 * Copyright 2020 OpenSynergy GmbH.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/dma-mapping.h>

#include "virtio_video.h"

static unsigned int debug;
module_param(debug, uint, 0644);

static unsigned int use_dma_mem;
module_param(use_dma_mem, uint, 0644);
MODULE_PARM_DESC(use_dma_mem, "Try to allocate buffers from the DMA zone");

static void *dma_phys_alloc(struct device *dev, size_t size,
			    dma_addr_t *dma_handle, gfp_t gfp,
			    unsigned long attrs)
{
	void *ret;

	ret = (void *)__get_free_pages(gfp, get_order(size));
	if (ret)
		*dma_handle = virt_to_phys(ret) - PFN_PHYS(dev->dma_pfn_offset);

	return ret;
}

static void dma_phys_free(struct device *dev, size_t size,
			  void *cpu_addr, dma_addr_t dma_addr,
			  unsigned long attrs)
{
	free_pages((unsigned long)cpu_addr, get_order(size));
}

static dma_addr_t dma_phys_map_page(struct device *dev, struct page *page,
				    unsigned long offset, size_t size,
				    enum dma_data_direction dir,
				    unsigned long attrs)
{
	return page_to_phys(page) + offset - PFN_PHYS(dev->dma_pfn_offset);
}

static int dma_phys_map_sg(struct device *dev, struct scatterlist *sgl,
			   int nents, enum dma_data_direction dir,
			   unsigned long attrs)
{
	int i;
	struct scatterlist *sg;

	for_each_sg(sgl, sg, nents, i) {
		dma_addr_t offset = PFN_PHYS(dev->dma_pfn_offset);
		void *va;

		BUG_ON(!sg_page(sg));
		va = sg_virt(sg);
		sg_dma_address(sg) = (dma_addr_t)virt_to_phys(va) - offset;
		sg_dma_len(sg) = sg->length;
	}

	return nents;
}

const struct dma_map_ops dma_phys_ops = {
	.alloc			= dma_phys_alloc,
	.free			= dma_phys_free,
	.map_page		= dma_phys_map_page,
	.map_sg			= dma_phys_map_sg,
};

static int virtio_video_probe(struct virtio_device *vdev)
{
	int ret;
	struct virtio_video_device *vvd;
	struct virtqueue *vqs[2];
	struct device *dev = &vdev->dev;

	static const char * const names[] = { "commandq", "eventq" };
	static vq_callback_t *callbacks[] = {
		virtio_video_cmd_cb,
		virtio_video_event_cb
	};

	if (!virtio_has_feature(vdev, VIRTIO_VIDEO_F_RESOURCE_GUEST_PAGES)) {
		dev_err(dev, "device must support guest allocated buffers\n");
		return -ENODEV;
	}

	vvd = devm_kzalloc(dev, sizeof(*vvd), GFP_KERNEL);
	if (!vvd)
		return -ENOMEM;

	vvd->vdev = vdev;
	vvd->debug = debug;
	vvd->use_dma_mem = use_dma_mem;
	vdev->priv = vvd;

	spin_lock_init(&vvd->resource_idr_lock);
	idr_init(&vvd->resource_idr);
	spin_lock_init(&vvd->stream_idr_lock);
	idr_init(&vvd->stream_idr);

	init_waitqueue_head(&vvd->wq);

	if (virtio_has_feature(vdev, VIRTIO_VIDEO_F_RESOURCE_NON_CONTIG))
		vvd->supp_non_contig = true;

	vvd->has_iommu = !virtio_has_iommu_quirk(vdev);
	if (!vvd->has_iommu)
		set_dma_ops(dev, &dma_phys_ops);

	dev_set_name(dev, "%s.%i", DRIVER_NAME, vdev->index);
	ret = v4l2_device_register(dev, &vvd->v4l2_dev);
	if (ret)
		goto err_v4l2_reg;

	spin_lock_init(&vvd->commandq.qlock);
	init_waitqueue_head(&vvd->commandq.reclaim_queue);

	spin_lock_init(&vvd->eventq.qlock);
	INIT_WORK(&vvd->eventq.reclaim_work, virtio_video_reclaim_events);

	ret = virtio_find_vqs(vdev, 2, vqs, callbacks, names, NULL);
	if (ret) {
		v4l2_err(&vvd->v4l2_dev, "failed to find virt queues\n");
		goto err_vqs;
	}

	vvd->commandq.vq = vqs[0];
	vvd->eventq.vq = vqs[1];

	ret = virtio_video_alloc_vbufs(vvd);
	if (ret) {
		v4l2_err(&vvd->v4l2_dev, "failed to alloc vbufs\n");
		goto err_vbufs;
	}

	virtio_cread(vdev, struct virtio_video_config, max_caps_length,
		     &vvd->max_caps_len);
	if (!vvd->max_caps_len) {
		v4l2_err(&vvd->v4l2_dev, "max_caps_len is zero\n");
		ret = -EINVAL;
		goto err_config;
	}

	virtio_cread(vdev, struct virtio_video_config, max_resp_length,
		     &vvd->max_resp_len);
	if (!vvd->max_resp_len) {
		v4l2_err(&vvd->v4l2_dev, "max_resp_len is zero\n");
		ret = -EINVAL;
		goto err_config;
	}

	ret = virtio_video_alloc_events(vvd, vvd->eventq.vq->num_free);
	if (ret)
		goto err_events;

	virtio_device_ready(vdev);
	vvd->vq_ready = true;

	ret = virtio_video_device_init(vvd);
	if (ret) {
		v4l2_err(&vvd->v4l2_dev,
			 "failed to init virtio video\n");
		goto err_init;
	}

	return 0;

err_init:
err_events:
err_config:
	virtio_video_free_vbufs(vvd);
err_vbufs:
	vdev->config->del_vqs(vdev);
err_vqs:
	v4l2_device_unregister(&vvd->v4l2_dev);
err_v4l2_reg:
	devm_kfree(&vdev->dev, vvd);

	return ret;
}

static void virtio_video_remove(struct virtio_device *vdev)
{
	struct virtio_video_device *vvd = vdev->priv;

	virtio_video_device_deinit(vvd);
	virtio_video_free_vbufs(vvd);
	vdev->config->del_vqs(vdev);
	v4l2_device_unregister(&vvd->v4l2_dev);
	devm_kfree(&vdev->dev, vvd);
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_VIDEO_DECODER, VIRTIO_DEV_ANY_ID },
	{ VIRTIO_ID_VIDEO_ENCODER, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
	VIRTIO_VIDEO_F_RESOURCE_GUEST_PAGES,
	VIRTIO_VIDEO_F_RESOURCE_NON_CONTIG,
};

static struct virtio_driver virtio_video_driver = {
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name = DRIVER_NAME,
	.driver.owner = THIS_MODULE,
	.id_table = id_table,
	.probe = virtio_video_probe,
	.remove = virtio_video_remove,
};

module_virtio_driver(virtio_video_driver);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("virtio video driver");
MODULE_AUTHOR("Dmitry Sepp <dmitry.sepp@opensynergy.com>");
MODULE_AUTHOR("Kiran Pawar <kiran.pawar@opensynergy.com>");
MODULE_AUTHOR("Nikolay Martyanov <nikolay.martyanov@opensynergy.com>");
MODULE_AUTHOR("Samiullah Khawaja <samiullah.khawaja@opensynergy.com>");
MODULE_LICENSE("GPL");
