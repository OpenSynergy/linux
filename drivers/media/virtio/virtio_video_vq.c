// SPDX-License-Identifier: GPL-2.0+
/* Driver for virtio video device.
 *
 * Copyright 2019 OpenSynergy GmbH.
 *
 * Based on drivers/gpu/drm/virtio/virtgpu_vq.c
 * Copyright (C) 2015 Red Hat, Inc.
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

#include "virtio_video.h"

#define MAX_INLINE_CMD_SIZE   298
#define MAX_INLINE_RESP_SIZE  298
#define VBUFFER_SIZE          (sizeof(struct virtio_video_vbuffer) \
			       + MAX_INLINE_CMD_SIZE		   \
			       + MAX_INLINE_RESP_SIZE)

void virtio_video_resource_id_get(struct virtio_video *vv, uint32_t *id)
{
	int handle;

	idr_preload(GFP_KERNEL);
	spin_lock(&vv->resource_idr_lock);
	handle = idr_alloc(&vv->resource_idr, NULL, 1, 0, GFP_NOWAIT);
	spin_unlock(&vv->resource_idr_lock);
	idr_preload_end();
	*id = handle;
}

void virtio_video_resource_id_put(struct virtio_video *vv, uint32_t id)
{
	spin_lock(&vv->resource_idr_lock);
	idr_remove(&vv->resource_idr, id);
	spin_unlock(&vv->resource_idr_lock);
}

void virtio_video_stream_id_get(struct virtio_video *vv,
				struct virtio_video_stream *stream,
				uint32_t *id)
{
	int handle;

	idr_preload(GFP_KERNEL);
	spin_lock(&vv->stream_idr_lock);
	handle = idr_alloc(&vv->stream_idr, stream, 1, 0, 0);
	spin_unlock(&vv->stream_idr_lock);
	idr_preload_end();
	*id = handle;
}

void virtio_video_stream_id_put(struct virtio_video *vv, uint32_t id)
{
	spin_lock(&vv->stream_idr_lock);
	idr_remove(&vv->stream_idr, id);
	spin_unlock(&vv->stream_idr_lock);
}

void virtio_video_ctrl_ack(struct virtqueue *vq)
{
	struct virtio_video *vv = vq->vdev->priv;

	schedule_work(&vv->ctrlq.dequeue_work);
}

void virtio_video_event_ack(struct virtqueue *vq)
{
	struct virtio_video *vv = vq->vdev->priv;

	schedule_work(&vv->eventq.dequeue_work);
}

static struct virtio_video_vbuffer *
virtio_video_get_vbuf(struct virtio_video *vv, int size,
		      int resp_size, void *resp_buf,
		      virtio_video_resp_cb resp_cb)
{
	struct virtio_video_vbuffer *vbuf;

	vbuf = kmem_cache_alloc(vv->vbufs, GFP_KERNEL);
	if (!vbuf)
		return ERR_PTR(-ENOMEM);
	memset(vbuf, 0, VBUFFER_SIZE);

	BUG_ON(size > MAX_INLINE_CMD_SIZE);
	vbuf->buf = (void *)vbuf + sizeof(*vbuf);
	vbuf->size = size;

	vbuf->resp_cb = resp_cb;
	vbuf->resp_size = resp_size;
	if (resp_size <= MAX_INLINE_RESP_SIZE && !resp_buf)
		vbuf->resp_buf = (void *)vbuf->buf + size;
	else
		vbuf->resp_buf = resp_buf;
	BUG_ON(!vbuf->resp_buf);

	return vbuf;
}

static void free_vbuf(struct virtio_video *vv,
		      struct virtio_video_vbuffer *vbuf)
{
	if (!vbuf->resp_cb &&
	    vbuf->resp_size > MAX_INLINE_RESP_SIZE)
		kfree(vbuf->resp_buf);
	kfree(vbuf->data_buf);
	kmem_cache_free(vv->vbufs, vbuf);
}

static void reclaim_vbufs(struct virtqueue *vq, struct list_head *reclaim_list)
{
	struct virtio_video_vbuffer *vbuf;
	unsigned int len;
	struct virtio_video *vv = vq->vdev->priv;
	int freed = 0;

	while ((vbuf = virtqueue_get_buf(vq, &len))) {
		list_add_tail(&vbuf->list, reclaim_list);
		freed++;
	}

	if (freed == 0)
		v4l2_dbg(1, vv->debug, &vv->v4l2_dev,
			 "zero vbufs reclaimed\n");
}

static void detach_vbufs(struct virtqueue *vq, struct list_head *detach_list)
{
	struct virtio_video_vbuffer *vbuf;

	while ((vbuf = virtqueue_detach_unused_buf(vq)) != NULL)
		list_add_tail(&vbuf->list, detach_list);
}

static void virtio_video_deatch_vbufs(struct virtio_video *vv)
{
	struct list_head detach_list;
	struct virtio_video_vbuffer *entry, *tmp;

	INIT_LIST_HEAD(&detach_list);

	detach_vbufs(vv->eventq.vq, &detach_list);
	detach_vbufs(vv->ctrlq.vq, &detach_list);

	if (list_empty(&detach_list))
		return;

	list_for_each_entry_safe(entry, tmp, &detach_list, list) {
		list_del(&entry->list);
		free_vbuf(vv, entry);
	}
}

int virtio_video_alloc_vbufs(struct virtio_video *vv)
{
	vv->vbufs =
		kmem_cache_create("virtio-video-vbufs", VBUFFER_SIZE,
				  __alignof__(struct virtio_video_vbuffer), 0,
				  NULL);
	if (!vv->vbufs)
		return -ENOMEM;

	return 0;
}

void virtio_video_free_vbufs(struct virtio_video *vv)
{
	virtio_video_deatch_vbufs(vv);
	kmem_cache_destroy(vv->vbufs);
	vv->vbufs = NULL;
}

static void *virtio_video_alloc_req(struct virtio_video *vv,
				    struct virtio_video_vbuffer **vbuffer_p,
				    int size)
{
	struct virtio_video_vbuffer *vbuf;

	vbuf = virtio_video_get_vbuf(vv, size,
				     sizeof(struct virtio_video_ctrl_hdr),
				     NULL, NULL);
	if (IS_ERR(vbuf)) {
		*vbuffer_p = NULL;
		return ERR_CAST(vbuf);
	}
	*vbuffer_p = vbuf;

	return vbuf->buf;
}

static void *
virtio_video_alloc_req_resp(struct virtio_video *vv,
			    virtio_video_resp_cb cb,
			    struct virtio_video_vbuffer **vbuffer_p,
			    int req_size, int resp_size,
			    void *resp_buf)
{
	struct virtio_video_vbuffer *vbuf;

	vbuf = virtio_video_get_vbuf(vv, req_size, resp_size, resp_buf, cb);
	if (IS_ERR(vbuf)) {
		*vbuffer_p = NULL;
		return ERR_CAST(vbuf);
	}
	*vbuffer_p = vbuf;

	return vbuf->buf;
}

void virtio_video_dequeue_ctrl_func(struct work_struct *work)
{
	struct virtio_video *vv =
		container_of(work, struct virtio_video,
			     ctrlq.dequeue_work);
	struct list_head reclaim_list;
	struct virtio_video_vbuffer *entry, *tmp;
	struct virtio_video_ctrl_hdr *resp;

	INIT_LIST_HEAD(&reclaim_list);
	spin_lock(&vv->ctrlq.qlock);
	do {
		virtqueue_disable_cb(vv->ctrlq.vq);
		reclaim_vbufs(vv->ctrlq.vq, &reclaim_list);

	} while (!virtqueue_enable_cb(vv->ctrlq.vq));
	spin_unlock(&vv->ctrlq.qlock);

	list_for_each_entry_safe(entry, tmp, &reclaim_list, list) {
		resp = (struct virtio_video_ctrl_hdr *)entry->resp_buf;
		if (resp->type >= cpu_to_le32(VIRTIO_VIDEO_S_ERR_UNSPEC))
			v4l2_dbg(1, vv->debug, &vv->v4l2_dev,
				 "response 0x%x\n", le32_to_cpu(resp->type));
		if (entry->resp_cb)
			entry->resp_cb(vv, entry);

		list_del(&entry->list);
		free_vbuf(vv, entry);
	}
	wake_up(&vv->ctrlq.ack_queue);
}

void virtio_video_dequeue_event_func(struct work_struct *work)
{
	struct virtio_video *vv =
		container_of(work, struct virtio_video,
			     eventq.dequeue_work);
	struct list_head reclaim_list;
	struct virtio_video_vbuffer *entry, *tmp;

	INIT_LIST_HEAD(&reclaim_list);
	spin_lock(&vv->eventq.qlock);
	do {
		virtqueue_disable_cb(vv->eventq.vq);
		reclaim_vbufs(vv->eventq.vq, &reclaim_list);

	} while (!virtqueue_enable_cb(vv->eventq.vq));
	spin_unlock(&vv->eventq.qlock);

	list_for_each_entry_safe(entry, tmp, &reclaim_list, list) {
		entry->resp_cb(vv, entry);
		list_del(&entry->list);
	}
	wake_up(&vv->eventq.ack_queue);
}

static int
virtio_video_queue_ctrl_buffer_locked(struct virtio_video *vv,
				      struct virtio_video_vbuffer *vbuf)
{
	struct virtqueue *vq = vv->ctrlq.vq;
	struct scatterlist *sgs[3], vreq, vout, vresp;
	int outcnt = 0, incnt = 0;
	int ret;

	if (!vv->vq_ready)
		return -ENODEV;

	sg_init_one(&vreq, vbuf->buf, vbuf->size);
	sgs[outcnt + incnt] = &vreq;
	outcnt++;

	if (vbuf->data_size) {
		sg_init_one(&vout, vbuf->data_buf, vbuf->data_size);
		sgs[outcnt + incnt] = &vout;
		outcnt++;
	}

	if (vbuf->resp_size) {
		sg_init_one(&vresp, vbuf->resp_buf, vbuf->resp_size);
		sgs[outcnt + incnt] = &vresp;
		incnt++;
	}

retry:
	ret = virtqueue_add_sgs(vq, sgs, outcnt, incnt, vbuf, GFP_ATOMIC);
	if (ret == -ENOSPC) {
		spin_unlock(&vv->ctrlq.qlock);
		wait_event(vv->ctrlq.ack_queue, vq->num_free);
		spin_lock(&vv->ctrlq.qlock);
		goto retry;
	} else {
		virtqueue_kick(vq);
	}

	return ret;
}

static int virtio_video_queue_ctrl_buffer(struct virtio_video *vv,
					  struct virtio_video_vbuffer *vbuf)
{
	int ret;

	spin_lock(&vv->ctrlq.qlock);
	ret = virtio_video_queue_ctrl_buffer_locked(vv, vbuf);
	spin_unlock(&vv->ctrlq.qlock);

	return ret;
}

static int virtio_video_queue_event_buffer(struct virtio_video *vv,
					   struct virtio_video_vbuffer *vbuf)
{
	int ret;
	struct scatterlist vresp;
	struct virtqueue *vq = vv->eventq.vq;

	spin_lock(&vv->eventq.qlock);
	sg_init_one(&vresp, vbuf->resp_buf, vbuf->resp_size);
	ret = virtqueue_add_inbuf(vq, &vresp, 1, vbuf, GFP_ATOMIC);
	spin_unlock(&vv->eventq.qlock);
	if (ret)
		return ret;

	virtqueue_kick(vq);

	return 0;
}

static void virtio_video_event_cb(struct virtio_video *vv,
				  struct virtio_video_vbuffer *vbuf)
{
	int ret;
	struct virtio_video_stream *stream;
	struct virtio_video_event *event =
		(struct virtio_video_event *)vbuf->resp_buf;

	stream = idr_find(&vv->stream_idr, event->stream_id);
	if (!stream) {
		v4l2_warn(&vv->v4l2_dev, "no stream %u found for event\n",
			  event->stream_id);
		return;
	}

	switch (le32_to_cpu(event->event_type)) {
	case VIRTIO_VIDEO_EVENT_T_RESOLUTION_CHANGED:
		virtio_video_req_get_params(vv, event->function_id,
					    VIDEO_PIN_TYPE_OUTPUT,
					    VIDEO_PARAMS_SCOPE_STREAM, stream);
		virtio_video_queue_res_chg_event(stream);
		break;
	case VIRTIO_VIDEO_EVENT_T_CONFIGURED:
		if (stream->state == STREAM_STATE_INIT) {
			stream->state = STREAM_STATE_METADATA;
			wake_up(&vv->wq);
		}
		break;
	default:
		v4l2_warn(&vv->v4l2_dev, "failed to queue event buffer\n");
		break;
	}

	memset(vbuf->resp_buf, 0, vbuf->resp_size);
	ret = virtio_video_queue_event_buffer(vv, vbuf);
	if (ret)
		v4l2_warn(&vv->v4l2_dev, "queue event buffer failed\n");
}

int virtio_video_alloc_events(struct virtio_video *vv, size_t num)
{
	int ret;
	size_t i;
	struct virtio_video_vbuffer *vbuf;

	for (i = 0; i < num; i++) {
		vbuf = virtio_video_get_vbuf(vv, 0,
					     sizeof(struct virtio_video_event),
					     NULL, virtio_video_event_cb);
		if (IS_ERR(vbuf))
			return PTR_ERR(vbuf);

		ret = virtio_video_queue_event_buffer(vv, vbuf);
		if (ret)
			return ret;
	}

	return 0;
}

int virtio_video_req_stream_create(struct virtio_video *vv,
				   uint32_t function_id, uint32_t stream_id,
				   const char *name)
{
	struct virtio_video_stream_create *req_p;
	struct virtio_video_vbuffer *vbuf;

	req_p = virtio_video_alloc_req(vv, &vbuf, sizeof(*req_p));
	if (IS_ERR(req_p))
		return PTR_ERR(req_p);
	memset(req_p, 0, sizeof(*req_p));

	req_p->hdr.type = cpu_to_le32(VIRTIO_VIDEO_T_STREAM_CREATE);
	req_p->hdr.stream_id = cpu_to_le32(stream_id);
	req_p->hdr.function_id = cpu_to_le32(function_id);
	strncpy(req_p->debug_name, name, sizeof(req_p->debug_name) - 1);
	req_p->debug_name[sizeof(req_p->debug_name) - 1] = 0;

	return virtio_video_queue_ctrl_buffer(vv, vbuf);
}

int virtio_video_req_stream_destroy(struct virtio_video *vv,
				    uint32_t function_id, uint32_t stream_id)
{
	struct virtio_video_stream_destroy *req_p;
	struct virtio_video_vbuffer *vbuf;

	req_p = virtio_video_alloc_req(vv, &vbuf, sizeof(*req_p));
	if (IS_ERR(req_p))
		return PTR_ERR(req_p);
	memset(req_p, 0, sizeof(*req_p));

	req_p->hdr.type = cpu_to_le32(VIRTIO_VIDEO_T_STREAM_DESTROY);
	req_p->hdr.stream_id = cpu_to_le32(stream_id);
	req_p->hdr.function_id = cpu_to_le32(function_id);

	return virtio_video_queue_ctrl_buffer(vv, vbuf);
}

int virtio_video_req_stream_start(struct virtio_video *vv,
				  uint32_t function_id, uint32_t stream_id)
{
	struct virtio_video_stream_start *req_p;
	struct virtio_video_vbuffer *vbuf;

	req_p = virtio_video_alloc_req(vv, &vbuf, sizeof(*req_p));
	if (IS_ERR(req_p))
		return PTR_ERR(req_p);
	memset(req_p, 0, sizeof(*req_p));

	req_p->hdr.type = cpu_to_le32(VIRTIO_VIDEO_T_STREAM_START);
	req_p->hdr.stream_id = cpu_to_le32(stream_id);
	req_p->hdr.function_id = cpu_to_le32(function_id);

	return virtio_video_queue_ctrl_buffer(vv, vbuf);
}

int virtio_video_req_stream_stop(struct virtio_video *vv,
				 uint32_t function_id,
				 struct virtio_video_stream *stream)
{
	struct virtio_video_stream_stop *req_p;
	struct virtio_video_vbuffer *vbuf;

	req_p = virtio_video_alloc_req(vv, &vbuf, sizeof(*req_p));
	if (IS_ERR(req_p))
		return PTR_ERR(req_p);
	memset(req_p, 0, sizeof(*req_p));

	req_p->hdr.type = cpu_to_le32(VIRTIO_VIDEO_T_STREAM_STOP);
	req_p->hdr.stream_id = cpu_to_le32(stream->stream_id);
	req_p->hdr.function_id = cpu_to_le32(function_id);

	vbuf->priv = stream;

	return virtio_video_queue_ctrl_buffer(vv, vbuf);
}

int virtio_video_req_stream_drain(struct virtio_video *vv,
				  uint32_t function_id, uint32_t stream_id)
{
	struct virtio_video_stream_drain *req_p;
	struct virtio_video_vbuffer *vbuf;

	req_p = virtio_video_alloc_req(vv, &vbuf, sizeof(*req_p));
	if (IS_ERR(req_p))
		return PTR_ERR(req_p);
	memset(req_p, 0, sizeof(*req_p));

	req_p->hdr.type = cpu_to_le32(VIRTIO_VIDEO_T_STREAM_DRAIN);
	req_p->hdr.stream_id = cpu_to_le32(stream_id);
	req_p->hdr.function_id = cpu_to_le32(function_id);

	return virtio_video_queue_ctrl_buffer(vv, vbuf);
}

int virtio_video_req_resource_create(struct virtio_video *vv,
				     uint32_t function_id, uint32_t stream_id,
				     uint32_t resource_id)
{
	struct virtio_video_resource_create *req_p;
	struct virtio_video_vbuffer *vbuf;

	req_p = virtio_video_alloc_req(vv, &vbuf, sizeof(*req_p));
	if (IS_ERR(req_p))
		return PTR_ERR(req_p);
	memset(req_p, 0, sizeof(*req_p));

	req_p->hdr.type = cpu_to_le32(VIRTIO_VIDEO_T_RESOURCE_CREATE);
	req_p->hdr.stream_id = cpu_to_le32(stream_id);
	req_p->hdr.function_id = cpu_to_le32(function_id);
	req_p->resource_id = cpu_to_le32(resource_id);

	return virtio_video_queue_ctrl_buffer(vv, vbuf);
}

int virtio_video_req_resource_destroy(struct virtio_video *vv,
				      uint32_t function_id, uint32_t stream_id,
				      uint32_t resource_id)
{
	struct virtio_video_resource_destroy *req_p;
	struct virtio_video_vbuffer *vbuf;

	req_p = virtio_video_alloc_req(vv, &vbuf, sizeof(*req_p));
	if (IS_ERR(req_p))
		return PTR_ERR(req_p);
	memset(req_p, 0, sizeof(*req_p));

	req_p->hdr.type = cpu_to_le32(VIRTIO_VIDEO_T_RESOURCE_DESTROY);
	req_p->hdr.stream_id = cpu_to_le32(stream_id);
	req_p->hdr.function_id = cpu_to_le32(function_id);
	req_p->resource_id = cpu_to_le32(resource_id);

	return virtio_video_queue_ctrl_buffer(vv, vbuf);
}

static void
virtio_video_req_resource_queue_cb(struct virtio_video *vv,
				   struct virtio_video_vbuffer *vbuf)
{
	uint32_t flags, bytesused;
	uint64_t timestamp;
	struct virtio_video_buffer *virtio_vb = vbuf->priv;
	struct virtio_video_resource_queue_resp *resp =
		(struct virtio_video_resource_queue_resp *)vbuf->resp_buf;

	flags = le32_to_cpu(resp->flags);
	bytesused = le32_to_cpu(resp->size);
	timestamp = le64_to_cpu(resp->timestamp);

	virtio_video_buf_done(virtio_vb, flags, timestamp, bytesused);
}

int virtio_video_req_resource_queue(struct virtio_video *vv,
				    uint32_t function_id, uint32_t stream_id,
				    struct virtio_video_buffer *virtio_vb,
				    uint32_t data_size[],
				    uint8_t num_data_size, bool is_in)
{
	uint8_t i;
	struct virtio_video_resource_queue *req_p;
	struct virtio_video_resource_queue_resp *resp_p;
	struct virtio_video_vbuffer *vbuf;
	size_t resp_size = sizeof(struct virtio_video_resource_queue_resp);

	req_p = virtio_video_alloc_req_resp(vv,
					    &virtio_video_req_resource_queue_cb,
					    &vbuf, sizeof(*req_p), resp_size,
					    NULL);
	if (IS_ERR(req_p))
		return PTR_ERR(req_p);
	memset(req_p, 0, sizeof(*req_p));

	req_p->hdr.type = cpu_to_le32(VIRTIO_VIDEO_T_RESOURCE_QUEUE);
	req_p->hdr.stream_id = cpu_to_le32(stream_id);
	req_p->hdr.function_id = cpu_to_le32(function_id);
	req_p->pin_type = cpu_to_le32(is_in ? VIRTIO_VIDEO_PIN_INPUT :
				      VIRTIO_VIDEO_PIN_OUTPUT);

	for (i = 0; i < num_data_size; ++i)
		req_p->data_size[i] = cpu_to_le32(data_size[i]);

	req_p->resource_id = cpu_to_le32(virtio_vb->resource_id);
	req_p->nr_data_size = num_data_size;
	req_p->timestamp =
		cpu_to_le64(virtio_vb->v4l2_m2m_vb.vb.vb2_buf.timestamp);

	resp_p = (struct virtio_video_resource_queue_resp *)vbuf->resp_buf;
	memset(resp_p, 0, sizeof(*resp_p));

	vbuf->priv = virtio_vb;

	return virtio_video_queue_ctrl_buffer(vv, vbuf);
}

int
virtio_video_req_resource_attach_backing(struct virtio_video *vv,
					 uint32_t function_id,
					 uint32_t stream_id,
					 uint32_t resource_id,
					 struct virtio_video_mem_entry *ents,
					 uint32_t nents)
{
	struct virtio_video_resource_attach_backing *req_p;
	struct virtio_video_vbuffer *vbuf;

	req_p = virtio_video_alloc_req(vv, &vbuf, sizeof(*req_p));
	if (IS_ERR(req_p))
		return PTR_ERR(req_p);
	memset(req_p, 0, sizeof(*req_p));

	req_p->hdr.type = cpu_to_le32(VIRTIO_VIDEO_T_RESOURCE_ATTACH_BACKING);
	req_p->hdr.stream_id = cpu_to_le32(stream_id);
	req_p->hdr.function_id = cpu_to_le32(function_id);
	req_p->resource_id = cpu_to_le32(resource_id);
	req_p->nr_entries = cpu_to_le32(nents);

	vbuf->data_buf = ents;
	vbuf->data_size = sizeof(*ents) * nents;

	return virtio_video_queue_ctrl_buffer(vv, vbuf);
}

static void
virtio_video_req_detach_backing_cb(struct virtio_video *vv,
				   struct virtio_video_vbuffer *vbuf)
{
	struct virtio_video_buffer *virtio_vb = vbuf->priv;

	virtio_vb->detached = true;
	wake_up(&vv->wq);
}

int
virtio_video_req_resource_detach_backing(struct virtio_video *vv,
					 uint32_t function_id,
					 uint32_t stream_id,
					 struct virtio_video_buffer *virtio_vb)
{
	struct virtio_video_resource_detach_backing *req_p;
	struct virtio_video_vbuffer *vbuf;

	req_p = virtio_video_alloc_req_resp
		(vv, &virtio_video_req_detach_backing_cb, &vbuf, sizeof(*req_p),
		 sizeof(struct virtio_video_ctrl_hdr), NULL);
	if (IS_ERR(req_p))
		return PTR_ERR(req_p);
	memset(req_p, 0, sizeof(*req_p));

	req_p->hdr.type = cpu_to_le32(VIRTIO_VIDEO_T_RESOURCE_DETACH_BACKING);
	req_p->hdr.stream_id = cpu_to_le32(stream_id);
	req_p->hdr.function_id = cpu_to_le32(function_id);
	req_p->resource_id = cpu_to_le32(virtio_vb->resource_id);
	vbuf->priv = virtio_vb;

	return virtio_video_queue_ctrl_buffer(vv, vbuf);
}

static void
virtio_video_req_queue_clear_cb(struct virtio_video *vv,
				struct virtio_video_vbuffer *vbuf)
{
	struct virtio_video_stream *stream = vbuf->priv;
	struct virtio_video_queue_clear *req_p =
		(struct virtio_video_queue_clear *)vbuf->buf;

	if (le32_to_cpu(req_p->pin_type) == VIRTIO_VIDEO_PIN_INPUT)
		stream->src_cleared = true;
	else
		stream->dst_cleared = true;

	wake_up(&vv->wq);
}

int virtio_video_req_queue_clear(struct virtio_video *vv, uint32_t function_id,
				 struct virtio_video_stream *stream,
				 bool is_in)
{
	struct virtio_video_queue_clear *req_p;
	struct virtio_video_vbuffer *vbuf;

	req_p = virtio_video_alloc_req_resp
		(vv, &virtio_video_req_queue_clear_cb, &vbuf, sizeof(*req_p),
		 sizeof(struct virtio_video_ctrl_hdr), NULL);
	if (IS_ERR(req_p))
		return PTR_ERR(req_p);
	memset(req_p, 0, sizeof(*req_p));

	req_p->hdr.type = cpu_to_le32(VIRTIO_VIDEO_T_QUEUE_CLEAR);
	req_p->hdr.stream_id = cpu_to_le32(stream->stream_id);
	req_p->hdr.function_id = cpu_to_le32(function_id);
	req_p->pin_type = cpu_to_le32(is_in ? VIRTIO_VIDEO_PIN_INPUT :
				      VIRTIO_VIDEO_PIN_OUTPUT);

	vbuf->priv = stream;

	return virtio_video_queue_ctrl_buffer(vv, vbuf);
}

static void
virtio_video_req_funcs_cb(struct virtio_video *vv,
			  struct virtio_video_vbuffer *vbuf)
{
	bool *got_resp_p = vbuf->priv;
	*got_resp_p = true;
	wake_up(&vv->wq);
}

int virtio_video_req_funcs(struct virtio_video *vv, void *resp_buf,
			   size_t resp_size)
{
	struct virtio_video_get_functions *req_p = NULL;
	struct virtio_video_vbuffer *vbuf = NULL;

	if (!vv || !resp_buf)
		return -1;

	req_p = virtio_video_alloc_req_resp(vv, &virtio_video_req_funcs_cb,
					    &vbuf, sizeof(*req_p), resp_size,
					    resp_buf);
	if (IS_ERR(req_p))
		return -1;

	memset(req_p, 0, sizeof(*req_p));

	req_p->hdr.type = cpu_to_le32(VIRTIO_VIDEO_T_GET_FUNCS);

	vbuf->priv = &vv->got_funcs;

	return virtio_video_queue_ctrl_buffer(vv, vbuf);
}

static void
virtio_video_req_get_params_cb(struct virtio_video *vv,
			       struct virtio_video_vbuffer *vbuf)
{
	int i;
	struct virtio_video_get_params_resp *resp =
		(struct virtio_video_get_params_resp *)vbuf->resp_buf;
	struct virtio_video_params *params = &resp->params;
	struct virtio_video_stream *stream = vbuf->priv;
	enum virtio_video_pin_type pin_type;
	enum virtio_video_scope_type scope;
	struct video_format_info *format_info = NULL;
	struct virtio_video_device *vvd  = NULL;

	pin_type = le32_to_cpu(params->pin_type);
	scope = le32_to_cpu(params->scope);

	vvd = to_virtio_vd(stream->video_dev);
	if (!vvd) {
		v4l2_warn(&vv->v4l2_dev, "no video device found\n");
		return;
	}

	if (scope == VIRTIO_VIDEO_SCOPE_STREAM) {
		if (pin_type == VIRTIO_VIDEO_PIN_INPUT)
			format_info = &stream->in_info;
		else
			format_info = &stream->out_info;
	} else {
		if (pin_type == VIRTIO_VIDEO_PIN_INPUT)
			format_info = &vvd->in_info;
		else
			format_info = &vvd->out_info;
	}

	if (!format_info)
		return;

	format_info->frame_rate = le32_to_cpu(params->frame_rate);
	format_info->frame_width = le32_to_cpu(params->frame_width);
	format_info->frame_height = le32_to_cpu(params->frame_height);
	format_info->min_buffers = le32_to_cpu(params->min_buffers);
	format_info->fourcc_format = virtio_video_format_to_v4l2(
			 le32_to_cpu(params->pixel_format));

	format_info->num_planes = le32_to_cpu(params->num_planes);
	for (i = 0; i < le32_to_cpu(params->num_planes); i++) {
		struct virtio_video_plane_format *plane_formats =
						 &params->plane_formats[i];
		struct video_plane_format *plane_format =
						 &format_info->plane_format[i];

		plane_format->channel = le32_to_cpu(plane_formats->channel);
		plane_format->plane_size =
				 le32_to_cpu(plane_formats->plane_size);
		plane_format->stride = le32_to_cpu(plane_formats->stride);
		plane_format->padding = le32_to_cpu(plane_formats->padding);
	}

	format_info->is_updated = true;
	wake_up(&vv->wq);
}

int virtio_video_req_get_params(struct virtio_video *vv, uint32_t function_id,
				enum video_pin_type pin_type,
				enum video_params_scope params_scope,
				struct virtio_video_stream *stream)
{
	int ret;
	struct virtio_video_get_params *req_p = NULL;
	struct virtio_video_vbuffer *vbuf = NULL;
	struct virtio_video_get_params_resp *resp_p;
	struct video_format_info *format_info = NULL;
	size_t resp_size = sizeof(struct virtio_video_get_params_resp);
	struct virtio_video_device *vvd  = NULL;

	if (!vv || !stream)
		return -1;

	req_p = virtio_video_alloc_req_resp(vv,
					&virtio_video_req_get_params_cb,
					&vbuf, sizeof(*req_p), resp_size,
					NULL);

	if (IS_ERR(req_p))
		return PTR_ERR(req_p);
	memset(req_p, 0, sizeof(*req_p));

	req_p->hdr.type = cpu_to_le32(VIRTIO_VIDEO_T_GET_PARAMS);
	req_p->hdr.stream_id = cpu_to_le32(stream->stream_id);
	req_p->hdr.function_id = cpu_to_le32(function_id);
	req_p->pin_type =
		cpu_to_le32(pin_type == VIDEO_PIN_TYPE_INPUT ?
			    VIRTIO_VIDEO_PIN_INPUT : VIRTIO_VIDEO_PIN_OUTPUT);
	req_p->scope =
		cpu_to_le32(params_scope == VIDEO_PARAMS_SCOPE_DEVICE ?
			    VIRTIO_VIDEO_SCOPE_GLOBAL :
			    VIRTIO_VIDEO_SCOPE_STREAM);
	resp_p = (struct virtio_video_get_params_resp *)vbuf->resp_buf;
	memset(resp_p, 0, sizeof(*resp_p));

	if (req_p->scope == VIRTIO_VIDEO_SCOPE_STREAM) {
		if (req_p->pin_type == VIRTIO_VIDEO_PIN_INPUT)
			format_info = &stream->in_info;
		else
			format_info = &stream->out_info;
	} else {
		vvd = to_virtio_vd(stream->video_dev);
		if (!vvd) {
			v4l2_warn(&vv->v4l2_dev, "no video device found\n");
			return -1;
		}
		if (req_p->pin_type == VIRTIO_VIDEO_PIN_INPUT)
			format_info = &vvd->in_info;
		else
			format_info = &vvd->out_info;
	}

	if (!format_info)
		return -1;

	format_info->is_updated = false;

	vbuf->priv = stream;
	ret = virtio_video_queue_ctrl_buffer(vv, vbuf);
	if (ret)
		return ret;

	ret = wait_event_timeout(vv->wq,
				 format_info->is_updated, 5 * HZ);
	if (ret == 0) {
		v4l2_err(&vv->v4l2_dev, "timed out waiting for get_params\n");
		return -1;
	}
	return 0;
}

int
virtio_video_req_set_params(struct virtio_video *vv, uint32_t function_id,
			    struct video_format_info *format_info,
			    enum video_pin_type pin_type,
			    enum video_params_scope params_scope,
			    struct virtio_video_stream *stream)
{
	int i;
	struct virtio_video_set_params *req_p;
	struct virtio_video_vbuffer *vbuf;

	req_p = virtio_video_alloc_req(vv, &vbuf, sizeof(*req_p));
	if (IS_ERR(req_p))
		return PTR_ERR(req_p);
	memset(req_p, 0, sizeof(*req_p));

	req_p->hdr.type = cpu_to_le32(VIRTIO_VIDEO_T_SET_PARAMS);
	req_p->hdr.stream_id = cpu_to_le32(stream->stream_id);
	req_p->hdr.function_id = cpu_to_le32(function_id);
	req_p->params.pin_type =
		cpu_to_le32(pin_type == VIDEO_PIN_TYPE_INPUT ?
			    VIRTIO_VIDEO_PIN_INPUT : VIRTIO_VIDEO_PIN_OUTPUT);
	req_p->params.scope =
		cpu_to_le32(params_scope == VIDEO_PARAMS_SCOPE_DEVICE ?
			    VIRTIO_VIDEO_SCOPE_GLOBAL :
			    VIRTIO_VIDEO_SCOPE_STREAM);
	req_p->params.frame_rate = cpu_to_le32(format_info->frame_rate);
	req_p->params.frame_width = cpu_to_le32(format_info->frame_width);
	req_p->params.frame_height =
				 cpu_to_le32(format_info->frame_height);
	req_p->params.pixel_format = virtio_video_v4l2_fourcc_to_virtio(
				 cpu_to_le32(format_info->fourcc_format));
	req_p->params.min_buffers = cpu_to_le32(format_info->min_buffers);
	req_p->params.num_planes = cpu_to_le32(format_info->num_planes);

	for (i = 0; i < format_info->num_planes; i++) {
		struct virtio_video_plane_format *plane_formats =
			&req_p->params.plane_formats[i];
		struct video_plane_format *plane_format =
			&format_info->plane_format[i];
		plane_formats->channel = cpu_to_le32(plane_format->channel);
		plane_formats->plane_size =
				 cpu_to_le32(plane_format->plane_size);
		plane_formats->stride = cpu_to_le32(plane_format->stride);
		plane_formats->padding = cpu_to_le32(plane_format->padding);
	}

	return virtio_video_queue_ctrl_buffer(vv, vbuf);
}

int virtio_video_req_set_control(struct virtio_video *vv,
				 uint32_t function_id, uint32_t stream_id,
				 uint32_t control, uint32_t val)
{
	struct virtio_video_set_control *req_p;
	struct virtio_video_vbuffer *vbuf;

	req_p = virtio_video_alloc_req(vv, &vbuf, sizeof(*req_p));
	if (IS_ERR(req_p))
		return PTR_ERR(req_p);
	memset(req_p, 0, sizeof(*req_p));

	req_p->hdr.type = cpu_to_le32(VIRTIO_VIDEO_T_SET_CONTROL);
	req_p->hdr.stream_id = cpu_to_le32(stream_id);
	req_p->hdr.function_id = cpu_to_le32(function_id);
	req_p->type = virtio_video_v4l2_control_to_virtio(cpu_to_le32(control));
	req_p->val = cpu_to_le64(val);

	return virtio_video_queue_ctrl_buffer(vv, vbuf);
}

