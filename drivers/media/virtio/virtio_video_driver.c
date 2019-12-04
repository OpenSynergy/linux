// SPDX-License-Identifier: GPL-2.0+
/*
 * Driver for virtio video device.
 *
 * Copyright 2019 OpenSynergy GmbH.
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

static void virtio_video_init_vq(struct virtio_video_queue *vvq,
				 void (*work_func)(struct work_struct *work))
{
	spin_lock_init(&vvq->qlock);
	init_waitqueue_head(&vvq->ack_queue);
	INIT_WORK(&vvq->dequeue_work, work_func);
}

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

static int virtio_video_init(struct virtio_video *vv)
{
	int ret = 0;
	void *resp_buf = NULL;
	void *funcs_buf = NULL;
	size_t total_resp_size = 0;

	if (!vv)
		return -EINVAL;

	total_resp_size = vv->funcs_size +
			  sizeof(struct virtio_video_get_functions);
	resp_buf = kzalloc(total_resp_size, GFP_KERNEL);
	if (IS_ERR(resp_buf))
		return -ENOMEM;

	ret = virtio_video_req_funcs(vv, resp_buf, total_resp_size);
	if (ret) {
		v4l2_err(&vv->v4l2_dev,
			 "failed to get devices from the host\n");
		goto err;
	}

	ret = wait_event_timeout(vv->wq, vv->got_funcs, 5 * HZ);
	if (ret == 0) {
		v4l2_err(&vv->v4l2_dev, "timed out waiting for get_funcs\n");
		ret = -EIO;
		goto err;
	}

	funcs_buf = resp_buf + sizeof(struct virtio_video_ctrl_hdr);
	ret = virtio_video_devices_init(vv, funcs_buf);
	if (ret) {
		v4l2_err(&vv->v4l2_dev, "failed to initialize devices\n");
		goto err;
	}

	kfree(resp_buf);
	return 0;

err:
	kfree(resp_buf);
	return ret;
};

static int virtio_video_probe(struct virtio_device *vdev)
{
	int ret;
	struct virtio_video *vv;
	struct virtqueue *vqs[2];
	struct device *dev = &vdev->dev;

	static const char * const names[] = { "control", "event" };
	static vq_callback_t *callbacks[] = {
		virtio_video_ctrl_ack,
		virtio_video_event_ack
	};

	vv = devm_kzalloc(dev, sizeof(*vv), GFP_KERNEL);
	if (!vv)
		return -ENOMEM;
	vv->vdev = vdev;
	vv->debug = debug;
	vdev->priv = vv;

	spin_lock_init(&vv->resource_idr_lock);
	idr_init(&vv->resource_idr);
	spin_lock_init(&vv->stream_idr_lock);
	idr_init(&vv->stream_idr);

	init_waitqueue_head(&vv->wq);

	vv->has_iommu = !virtio_has_iommu_quirk(vdev);
	if (!vv->has_iommu)
		set_dma_ops(dev, &dma_phys_ops);

	dev_set_name(dev, DRIVER_NAME);
	ret = v4l2_device_register(dev, &vv->v4l2_dev);
	if (ret)
		goto err_v4l2_reg;

	virtio_video_init_vq(&vv->ctrlq, virtio_video_dequeue_ctrl_func);
	virtio_video_init_vq(&vv->eventq, virtio_video_dequeue_event_func);

	ret = virtio_find_vqs(vdev, 2, vqs, callbacks, names, NULL);
	if (ret) {
		v4l2_err(&vv->v4l2_dev, "failed to find virt queues\n");
		goto err_vqs;
	}

	vv->ctrlq.vq = vqs[0];
	vv->eventq.vq = vqs[1];

	ret = virtio_video_alloc_vbufs(vv);
	if (ret) {
		v4l2_err(&vv->v4l2_dev, "failed to alloc vbufs\n");
		goto err_vbufs;
	}

	virtio_cread(vdev, struct virtio_video_config, total_functions_size,
		     &vv->funcs_size);
	if (!vv->funcs_size) {
		v4l2_err(&vv->v4l2_dev, "virtio_functions_size is zero\n");
		ret = -EINVAL;
		goto err_config;
	}

	virtio_cread(vdev, struct virtio_video_config, num_functions,
		     &vv->num_devices);
	if (!vv->num_devices) {
		v4l2_err(&vv->v4l2_dev, "num_devices is zero\n");
		ret = -EINVAL;
		goto err_config;
	}

	ret = virtio_video_alloc_events(vv, vv->eventq.vq->num_free);
	if (ret)
		goto err_events;

	virtio_device_ready(vdev);
	vv->vq_ready = true;
	vv->got_funcs = false;

	INIT_LIST_HEAD(&vv->devices_list);

	ret = virtio_video_init(vv);
	if (ret) {
		v4l2_err(&vv->v4l2_dev,
			 "failed to init virtio video\n");
		goto err_init;
	}

	return 0;

err_init:
err_events:
err_config:
	virtio_video_free_vbufs(vv);
err_vbufs:
	vdev->config->del_vqs(vdev);
err_vqs:
	v4l2_device_unregister(&vv->v4l2_dev);
err_v4l2_reg:
	devm_kfree(&vdev->dev, vv);

	return ret;
}

static void virtio_video_remove(struct virtio_device *vdev)
{
	struct virtio_video *vv = vdev->priv;

	virtio_video_devices_deinit(vv);
	virtio_video_free_vbufs(vv);
	vdev->config->del_vqs(vdev);
	v4l2_device_unregister(&vv->v4l2_dev);
	devm_kfree(&vdev->dev, vv);
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_VIDEO, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
	/* none */
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
MODULE_AUTHOR("Dmitry Morozov <dmitry.morozov@opensynergy.com>");
MODULE_AUTHOR("Kiran Pawar <kiran.pawar@opensynergy.com>");
MODULE_AUTHOR("Nikolay Martyanov <nikolay.martyanov@opensynergy.com>");
MODULE_LICENSE("GPL");
