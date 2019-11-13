// SPDX-License-Identifier: GPL-2.0+
/*
 * Sound card driver for virtio
 * Copyright (C) 2019  OpenSynergy GmbH
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

#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/sched/rt.h>
#include <linux/sched/types.h>
#include <linux/version.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_snd.h>

#include <sound/core.h>
#include <sound/initval.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>

#ifndef SNDRV_PCM_FORMAT_S24_3
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define SNDRV_PCM_FORMAT_S24_3 SNDRV_PCM_FORMAT_S24_3LE
#else
#define SNDRV_PCM_FORMAT_S24_3 SNDRV_PCM_FORMAT_S24_3BE
#endif
#endif

#ifndef SNDRV_PCM_FORMAT_U24_3
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define SNDRV_PCM_FORMAT_U24_3 SNDRV_PCM_FORMAT_U24_3LE
#else
#define SNDRV_PCM_FORMAT_U24_3 SNDRV_PCM_FORMAT_U24_3BE
#endif
#endif

#ifndef SNDRV_PCM_FORMAT_S20_3
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define SNDRV_PCM_FORMAT_S20_3 SNDRV_PCM_FORMAT_S20_3LE
#else
#define SNDRV_PCM_FORMAT_S20_3 SNDRV_PCM_FORMAT_S20_3BE
#endif
#endif

#ifndef SNDRV_PCM_FORMAT_U20_3
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define SNDRV_PCM_FORMAT_U20_3 SNDRV_PCM_FORMAT_U20_3LE
#else
#define SNDRV_PCM_FORMAT_U20_3 SNDRV_PCM_FORMAT_U20_3BE
#endif
#endif

#ifndef SNDRV_PCM_FORMAT_S18_3
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define SNDRV_PCM_FORMAT_S18_3 SNDRV_PCM_FORMAT_S18_3LE
#else
#define SNDRV_PCM_FORMAT_S18_3 SNDRV_PCM_FORMAT_S18_3BE
#endif
#endif

#ifndef SNDRV_PCM_FORMAT_U18_3
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define SNDRV_PCM_FORMAT_U18_3 SNDRV_PCM_FORMAT_U18_3LE
#else
#define SNDRV_PCM_FORMAT_U18_3 SNDRV_PCM_FORMAT_U18_3BE
#endif
#endif

static int pcm_xfer_ms = 10;
module_param(pcm_xfer_ms, int, 0644);
MODULE_PARM_DESC(pcm_xfer_ms, "PCM transfer block size in milliseconds.");

typedef void viosnd_vq_callback_t(struct virtqueue *, void *);

/* control message proxy structure */
struct viosnd_msg;
typedef void viosnd_ctl_callback_t(struct viosnd_msg *msg);

struct viosnd_msg {
	bool notify;
	wait_queue_head_t wait_completed;
	bool completed;
	viosnd_ctl_callback_t *cb;
	void *cb_data;
	struct virtio_snd_hdr *request;
	size_t request_size;
	struct virtio_snd_hdr *response;
	size_t response_size;
};

/* virtual queue proxy structure */
struct viosnd_queue {
	struct virtqueue *queue;
	viosnd_vq_callback_t *cb;
	void *cb_data;
};

/* device private context structure */
struct viosnd_ctx {
	struct virtio_device *vdev;
	struct snd_card *card;
	/* queues management */
	struct viosnd_queue *queues;
	u32 queue_count;
	u32 queue_max_count;
	/* control queue */
	spinlock_t lock;
	struct virtqueue *ctl_queue;
	unsigned int msg_count;
	wait_queue_head_t wait_available;
};

struct viosnd_pcm;
struct viosnd_pcm_stream;
struct viosnd_pcm_substream;

/* PCM message proxy structure */
struct viosnd_pcm_msg {
	struct virtio_snd_pcm_xfer request;
	struct virtio_snd_pcm_status response;
};

struct viosnd_pcm_stream {
	struct viosnd_pcm *pcm;

	struct snd_pcm_hardware hw;
	struct snd_pcm_hw_constraint_list period_size_list;
	struct snd_pcm_substream *substream;
	u8 nchmaps;

	u8 *data;
	snd_pcm_uframes_t period_position;
	snd_pcm_uframes_t xfer_idle_size;
	u64 xfer_start_ns;
	u64 xfer_carry_ns;
	u64 pause_ns;

	/* simulated hardware pointer */
	struct {
		snd_pcm_uframes_t value;
		snd_pcm_uframes_t carry_value;
		u64 begin_ns;
	} hw_ptr;

	/* playback shadow buffer */
	struct {
		u8 *data;
		snd_pcm_uframes_t host_position;
		snd_pcm_uframes_t guest_position;
	} shadow;

	struct task_struct *thread;
	/* protects all fields shared with a thread */
	spinlock_t thread_lock;
	wait_queue_head_t thread_wait_idle;
	wait_queue_head_t thread_wait_busy;
	bool thread_idle;
	bool thread_busy;
};

struct viosnd_pcm {
	struct viosnd_ctx *ctx;
	struct snd_pcm *pcm;
	struct viosnd_pcm_stream *streams[2];
	/* protects PCM data queue */
	spinlock_t lock;
	/* PCM data queue */
	struct virtqueue *queue;
	unsigned int msg_count;
};

static void viosnd_notify_cb(struct virtqueue *vqueue)
{
	struct viosnd_ctx *ctx = vqueue->vdev->priv;
	unsigned int queue_id;

	for (queue_id = 0; queue_id < ctx->queue_count; ++queue_id) {
		struct viosnd_queue *queue = ctx->queues + queue_id;

		if (queue->queue == vqueue) {
			if (queue->cb)
				queue->cb(vqueue, queue->cb_data);

			break;
		}
	}
}

static struct virtqueue *viosnd_queue_assign(struct viosnd_ctx *ctx,
					     viosnd_vq_callback_t *cb,
					     void *data)
{
	struct virtqueue *vqueue = ERR_PTR(-ENOENT);

	if (ctx->queue_count < ctx->queue_max_count) {
		struct viosnd_queue *queue = ctx->queues + ctx->queue_count++;

		vqueue = queue->queue;

		if (cb) {
			queue->cb = cb;
			queue->cb_data = data;
			virtqueue_enable_cb(vqueue);
		}
	}

	return vqueue;
}

static inline bool viosnd_ctl_msg_wait_available(struct viosnd_ctx *ctx,
						 unsigned int msecs)
{
	int code;
	unsigned long js = msecs_to_jiffies(msecs);

	if (!js)
		return false;

	code = wait_event_interruptible_lock_irq_timeout(ctx->wait_available,
							 ctx->msg_count,
							 ctx->lock,
							 js);

	return (code > 0) ? true : false;
}

static struct viosnd_msg *viosnd_ctl_msg_get(struct viosnd_ctx *ctx,
					     size_t request_size,
					     size_t response_size,
					     gfp_t gfp,
					     unsigned int msecs)
{
	struct device *dev = &ctx->vdev->dev;
	struct viosnd_msg *msg;
	unsigned long flags;

	msg = devm_kzalloc(dev, sizeof(*msg), gfp);
	if (!msg)
		return ERR_PTR(-ENOMEM);

	msg->request = devm_kzalloc(dev, request_size, gfp);
	if (!msg->request) {
		devm_kfree(dev, msg);
		return ERR_PTR(-ENOMEM);
	}

	msg->response = devm_kzalloc(dev, response_size, gfp);
	if (!msg->response) {
		devm_kfree(dev, msg->request);
		devm_kfree(dev, msg);
		return ERR_PTR(-ENOMEM);
	}

	msg->request_size = request_size;
	msg->response_size = response_size;
	init_waitqueue_head(&msg->wait_completed);

	spin_lock_irqsave(&ctx->lock, flags);
	if (!ctx->msg_count)
		if (!viosnd_ctl_msg_wait_available(ctx, msecs)) {
			devm_kfree(dev, msg->response);
			devm_kfree(dev, msg->request);
			devm_kfree(dev, msg);
			msg = ERR_PTR(-ENOENT);
			goto on_failure;
		}

	ctx->msg_count--;

on_failure:
	spin_unlock_irqrestore(&ctx->lock, flags);

	return msg;
}

static void viosnd_ctl_msg_put_nolock(struct viosnd_ctx *ctx,
				      struct viosnd_msg *msg)
{
	struct device *dev = &ctx->vdev->dev;

	devm_kfree(dev, msg->response);
	devm_kfree(dev, msg->request);
	devm_kfree(dev, msg);

	ctx->msg_count++;
	wake_up(&ctx->wait_available);
}

static void viosnd_ctl_msg_put(struct viosnd_ctx *ctx, struct viosnd_msg *msg)
{
	unsigned long flags;

	spin_lock_irqsave(&ctx->lock, flags);
	viosnd_ctl_msg_put_nolock(ctx, msg);
	spin_unlock_irqrestore(&ctx->lock, flags);
}

static void viosnd_ctl_notify_cb(struct virtqueue *vqueue, void *data)
{
	struct viosnd_ctx *ctx = data;
	unsigned long flags;

	spin_lock_irqsave(&ctx->lock, flags);

	do {
		struct viosnd_msg *msg;
		unsigned int length;

		virtqueue_disable_cb(vqueue);

		while ((msg = virtqueue_get_buf(vqueue, &length))) {
			if (msg->notify) {
				msg->completed = true;
				wake_up(&msg->wait_completed);

				continue;
			}

			if (msg->cb)
				msg->cb(msg);

			viosnd_ctl_msg_put_nolock(ctx, msg);
		}

		if (unlikely(virtqueue_is_broken(vqueue)))
			break;
	} while (!virtqueue_enable_cb(vqueue));

	spin_unlock_irqrestore(&ctx->lock, flags);
}

static inline int viosnd_ctl_msg_status(u32 status)
{
	switch (status) {
	case VIRTIO_SND_S_OK:
		return 0;
	case VIRTIO_SND_S_ENOTSUPPORTED:
		return -EOPNOTSUPP;
	case VIRTIO_SND_S_EINVALID:
		return -EINVAL;
	case VIRTIO_SND_S_EIO:
		return -EIO;
	default:
		return -EPERM;
	}
}

static inline int viosnd_ctl_msg_wait_completed(struct viosnd_msg *msg,
						unsigned int msecs)
{
	int code;

	code = wait_event_interruptible_timeout(msg->wait_completed,
						msg->completed,
						msecs_to_jiffies(msecs));

	if (code > 0)
		code = viosnd_ctl_msg_status(le32_to_cpu(msg->response->code));
	else
		code = -EIO;

	return code;
}

static inline int viosnd_ctl_msg_send(struct viosnd_ctx *ctx,
				      struct viosnd_msg *msg,
				      unsigned int msecs)
{
	int code;
	struct scatterlist sg_request;
	struct scatterlist sg_response;
	struct scatterlist *sgs[2] = { &sg_request, &sg_response };
	bool notify = false;
	unsigned long flags;

	msg->completed = false;
	msg->notify = !!msecs;

	sg_init_one(&sg_request, msg->request, msg->request_size);
	sg_init_one(&sg_response, msg->response, msg->response_size);

	spin_lock_irqsave(&ctx->lock, flags);
	code = virtqueue_add_sgs(ctx->ctl_queue, sgs, 1, 1, msg, GFP_ATOMIC);
	if (!code)
		notify = virtqueue_kick_prepare(ctx->ctl_queue);
	spin_unlock_irqrestore(&ctx->lock, flags);

	if (!code) {
		if (notify)
			virtqueue_notify(ctx->ctl_queue);

		if (msg->notify)
			code = viosnd_ctl_msg_wait_completed(msg, msecs);
	}

	return code;
}

static inline struct viosnd_pcm_stream *
viosnd_pcm_substream_ctx(struct snd_pcm_substream *substream)
{
	struct viosnd_pcm *pcm = substream->private_data;

	switch (substream->stream) {
	case SNDRV_PCM_STREAM_PLAYBACK:
		return pcm->streams[VIRTIO_SND_PCM_T_PLAYBACK];
	case SNDRV_PCM_STREAM_CAPTURE:
		return pcm->streams[VIRTIO_SND_PCM_T_CAPTURE];
	}

	return NULL;
}

static inline snd_pcm_uframes_t
viosnd_pcm_period_size(struct viosnd_pcm_stream *stream)
{
	struct snd_pcm_runtime *runtime = stream->substream->runtime;

	return (runtime->rate * pcm_xfer_ms) / MSEC_PER_SEC;
}

static inline unsigned int
viosnd_pcm_frames_to_us(struct viosnd_pcm_stream *stream,
			snd_pcm_uframes_t frames)
{
	struct snd_pcm_runtime *runtime = stream->substream->runtime;

	return ((frames * MSEC_PER_SEC) / runtime->rate) * USEC_PER_MSEC;
}

static inline void viosnd_pcm_set_hdr(struct virtio_snd_pcm_hdr *hdr,
				      struct viosnd_pcm_stream *stream,
				      u32 request)
{
	struct virtio_device *vdev = stream->pcm->ctx->vdev;

	hdr->hdr.code = cpu_to_virtio32(vdev, request);
	hdr->pcm_id = stream->pcm->pcm->device;
	hdr->stream_type =
		(stream->substream->stream == SNDRV_PCM_STREAM_PLAYBACK) ?
			VIRTIO_SND_PCM_T_PLAYBACK :
			VIRTIO_SND_PCM_T_CAPTURE;
}

static int viosnd_pcm_send_generic_cb(struct viosnd_pcm_stream *stream,
				      u32 command, gfp_t gfp,
				      unsigned int msecs,
				      viosnd_ctl_callback_t *cb)
{
	int code;
	struct viosnd_ctx *ctx = stream->pcm->ctx;
	struct viosnd_msg *msg;

	msg = viosnd_ctl_msg_get(ctx, sizeof(struct virtio_snd_pcm_hdr),
				 sizeof(struct virtio_snd_hdr), gfp, msecs);
	if (IS_ERR(msg))
		return PTR_ERR(msg);

	viosnd_pcm_set_hdr((struct virtio_snd_pcm_hdr *)msg->request, stream,
			   command);

	if (!msecs) {
		msg->cb = cb;
		msg->cb_data = stream;
	}

	code = viosnd_ctl_msg_send(ctx, msg, msecs);

	if (msecs)
		viosnd_ctl_msg_put(ctx, msg);

	return code;
}

static int viosnd_pcm_send_generic(struct viosnd_pcm_stream *stream,
				   u32 command, gfp_t gfp, unsigned int msecs)
{
	return viosnd_pcm_send_generic_cb(stream, command, gfp, msecs, NULL);
}

static inline void viosnd_pcm_xfer_enqueue(struct viosnd_pcm_stream *stream,
					   void *data, size_t size, gfp_t gfp)
{
	struct viosnd_pcm *pcm = stream->pcm;
	struct virtio_device *vdev = pcm->ctx->vdev;
	struct device *dev = &vdev->dev;
	struct viosnd_pcm_msg *msg;
	unsigned long flags;

	msg = devm_kzalloc(dev, sizeof(*msg), gfp);
	if (!msg)
		return;

	msg->request.address = cpu_to_virtio64(vdev, virt_to_phys(data));
	msg->request.length = cpu_to_virtio32(vdev, size);
	msg->request.stream_type =
		(stream->substream->stream == SNDRV_PCM_STREAM_PLAYBACK) ?
			VIRTIO_SND_PCM_T_PLAYBACK :
			VIRTIO_SND_PCM_T_CAPTURE;

	spin_lock_irqsave(&pcm->lock, flags);
	if (pcm->msg_count) {
		struct scatterlist sg_out;
		struct scatterlist sg_in;
		struct scatterlist *sgs[2] = { &sg_out, &sg_in };

		sg_init_one(&sg_out, &msg->request, sizeof(msg->request));
		sg_init_one(&sg_in, &msg->response, sizeof(msg->response));

		if (!virtqueue_add_sgs(pcm->queue, sgs, 1, 1, msg, GFP_ATOMIC))
			pcm->msg_count--;
	}
	spin_unlock_irqrestore(&pcm->lock, flags);
}

static inline snd_pcm_sframes_t
viosnd_pcm_size(struct viosnd_pcm_stream *stream, snd_pcm_uframes_t hw_ptr,
		snd_pcm_uframes_t appl_ptr)
{
	struct snd_pcm_runtime *runtime = stream->substream->runtime;
	snd_pcm_sframes_t frames;

	frames = hw_ptr + runtime->buffer_size - appl_ptr;
	if (frames < 0)
		frames += runtime->boundary;
	else if ((snd_pcm_uframes_t)frames >= runtime->boundary)
		frames -= runtime->boundary;

	return (snd_pcm_sframes_t)runtime->buffer_size - frames;
}

static inline snd_pcm_sframes_t
viosnd_pcm_shadow_size(struct viosnd_pcm_stream *stream)
{
	return viosnd_pcm_size(stream, stream->shadow.host_position,
			       stream->shadow.guest_position);
}

static void viosnd_pcm_copy_to_shadow(struct viosnd_pcm_stream *stream,
				      snd_pcm_uframes_t frames)
{
	struct snd_pcm_runtime *runtime = stream->substream->runtime;

	while (frames) {
		snd_pcm_uframes_t position =
			stream->shadow.guest_position % runtime->buffer_size;
		snd_pcm_uframes_t count = frames;
		void *src;
		void *dst;

		if (position + count > runtime->buffer_size)
			count = runtime->buffer_size - position;

		src = stream->data + frames_to_bytes(runtime, position);
		dst = stream->shadow.data + frames_to_bytes(runtime, position);

		memcpy(dst, src, frames_to_bytes(runtime, count));

		stream->shadow.guest_position += count;
		if (stream->shadow.guest_position >= runtime->boundary)
			stream->shadow.guest_position -= runtime->boundary;

		frames -= count;
	}
}

static void viosnd_pcm_xfer_write(struct viosnd_pcm_stream *stream,
				  snd_pcm_uframes_t frames, gfp_t gfp)
{
	struct viosnd_pcm *pcm = stream->pcm;
	struct snd_pcm_runtime *runtime = stream->substream->runtime;
	bool notify = false;
	unsigned long flags;

	while (frames) {
		snd_pcm_uframes_t position =
			stream->shadow.host_position % runtime->buffer_size;
		snd_pcm_uframes_t count = frames;
		void *data;

		if (position + count > runtime->buffer_size)
			count = runtime->buffer_size - position;

		data = stream->shadow.data + frames_to_bytes(runtime, position);

		viosnd_pcm_xfer_enqueue(stream, data,
					frames_to_bytes(runtime, count), gfp);

		stream->shadow.host_position += count;
		if (stream->shadow.host_position >= runtime->boundary)
			stream->shadow.host_position -= runtime->boundary;

		frames -= count;
	}

	spin_lock_irqsave(&pcm->lock, flags);
	notify = virtqueue_kick_prepare(pcm->queue);
	spin_unlock_irqrestore(&pcm->lock, flags);

	if (notify)
		virtqueue_notify(pcm->queue);
}

static void viosnd_pcm_xfer_read(struct viosnd_pcm_stream *stream,
				 snd_pcm_uframes_t frames, gfp_t gfp)
{
	struct viosnd_pcm *pcm = stream->pcm;
	struct snd_pcm_runtime *runtime = stream->substream->runtime;
	snd_pcm_uframes_t position =
		stream->hw_ptr.value % runtime->buffer_size;
	bool notify = false;
	unsigned long flags;

	while (frames) {
		snd_pcm_uframes_t count = frames;
		void *data;

		if (position + count > runtime->buffer_size)
			count = runtime->buffer_size - position;

		data = stream->data + frames_to_bytes(runtime, position);

		viosnd_pcm_xfer_enqueue(stream, data,
					frames_to_bytes(runtime, count), gfp);

		position = (position + count) % runtime->buffer_size;
		frames -= count;
	}

	spin_lock_irqsave(&pcm->lock, flags);
	notify = virtqueue_kick_prepare(pcm->queue);
	spin_unlock_irqrestore(&pcm->lock, flags);

	if (notify)
		virtqueue_notify(pcm->queue);
}

static int viosnd_pcm_stream_fn(void *data)
{
	struct viosnd_pcm_stream *stream = data;
	struct snd_pcm_substream *substream = stream->substream;
	bool is_playback = (substream->stream == SNDRV_PCM_STREAM_PLAYBACK);
	unsigned long us = 0;
	unsigned long flags;

on_restart:
	spin_lock_irqsave(&stream->thread_lock, flags);
	stream->thread_idle = true;
	wake_up_all(&stream->thread_wait_idle);

	while (!stream->thread_busy && !kthread_should_stop())
		/* Timeout is used for calming down kernel hang checker: */
		wait_event_lock_irq_timeout(stream->thread_wait_busy,
					    stream->thread_busy ||
					    kthread_should_stop(),
					    stream->thread_lock,
					    msecs_to_jiffies(MSEC_PER_SEC));

	stream->thread_idle = false;

	if (stream->thread_busy)
		us = viosnd_pcm_frames_to_us(stream, stream->xfer_idle_size);
	spin_unlock_irqrestore(&stream->thread_lock, flags);

	while (!kthread_should_stop()) {
		snd_pcm_uframes_t xfer_size = 0;
		bool thread_busy;

		if (us)
			usleep_range(us, us);

		if (kthread_should_stop())
			break;

		spin_lock(&stream->thread_lock);
		thread_busy = stream->thread_busy;
		if (thread_busy || stream->pause_ns) {
			u64 carry_ns = stream->xfer_carry_ns;
			u64 ns;
			unsigned int rate = substream->runtime->rate;

			if (stream->pause_ns) {
				ns = stream->pause_ns - stream->xfer_start_ns;
			} else {
				u64 current_ns = ktime_get_raw_ns();

				ns = current_ns - stream->xfer_start_ns;
				stream->xfer_start_ns = current_ns;
			}

			xfer_size = (rate * ns + carry_ns) / NSEC_PER_SEC;
			stream->xfer_carry_ns =
				(rate * ns + carry_ns) % NSEC_PER_SEC;

			if (stream->pause_ns) {
				snd_pcm_uframes_t period_size =
					viosnd_pcm_period_size(stream);

				if (xfer_size < period_size)
					stream->xfer_idle_size =
						period_size - xfer_size;
				else
					stream->xfer_idle_size = 0;

				stream->pause_ns = 0;
			}

			if (is_playback) {
				snd_pcm_sframes_t size;

				size = viosnd_pcm_shadow_size(stream);
				if (size < xfer_size) {
					size = xfer_size - size;

					viosnd_pcm_copy_to_shadow(stream, size);
				}
			}
		}
		spin_unlock(&stream->thread_lock);

		if (xfer_size) {
			if (is_playback)
				viosnd_pcm_xfer_write(stream, xfer_size,
						      GFP_KERNEL);
			else
				viosnd_pcm_xfer_read(stream, xfer_size,
						     GFP_KERNEL);
		}

		if (!thread_busy)
			goto on_restart;

		us = pcm_xfer_ms * USEC_PER_MSEC;
	}

	return 0;
}

static void viosnd_pcm_notify_cb(struct virtqueue *vqueue, void *data)
{
	struct viosnd_pcm *pcm = data;
	struct device *dev = &pcm->ctx->vdev->dev;

	do {
		virtqueue_disable_cb(vqueue);

		for (;;) {
			struct viosnd_pcm_msg *msg;
			struct viosnd_pcm_stream *ctx = NULL;
			struct snd_pcm_substream *substream;
			struct snd_pcm_runtime *runtime;
			unsigned long flags;
			u32 length;
			bool period_elapsed = false;

			spin_lock_irqsave(&pcm->lock, flags);
			msg = virtqueue_get_buf(vqueue, &length);
			if (msg)
				pcm->msg_count++;
			spin_unlock_irqrestore(&pcm->lock, flags);

			if (!msg)
				break;

			switch (msg->request.stream_type) {
			case VIRTIO_SND_PCM_T_PLAYBACK:
			case VIRTIO_SND_PCM_T_CAPTURE:
				ctx = pcm->streams[msg->request.stream_type];

				break;
			}

			if (ctx)
				length = le32_to_cpu(msg->response.length);

			devm_kfree(dev, msg);

			if (!ctx) {
				dev_warn(dev, "Malformed message response");
				continue;
			}

			substream = ctx->substream;
			runtime = substream->runtime;

			snd_pcm_stream_lock(substream);

			if (substream->stream == SNDRV_PCM_STREAM_CAPTURE) {
				ctx->hw_ptr.value +=
					bytes_to_frames(runtime, length);
				if (ctx->hw_ptr.value >= runtime->boundary)
					ctx->hw_ptr.value -= runtime->boundary;
			}

			ctx->period_position +=
				bytes_to_frames(runtime, length);
			if (ctx->period_position >= runtime->period_size) {
				ctx->period_position -= runtime->period_size;
				period_elapsed = true;
			}

			snd_pcm_stream_unlock(substream);

			if (period_elapsed)
				snd_pcm_period_elapsed(substream);
		}

		if (unlikely(virtqueue_is_broken(vqueue)))
			break;
	} while (!virtqueue_enable_cb(vqueue));
}

static int viosnd_pcm_open(struct snd_pcm_substream *substream)
{
	int code;
	struct viosnd_pcm_stream *stream = viosnd_pcm_substream_ctx(substream);
	struct sched_param sched_params = {
		.sched_priority = MAX_RT_PRIO - 1
	};

	if (!stream)
		return -EBADFD;

	stream->thread_idle = true;
	stream->thread_busy = false;

	stream->thread = kthread_run(viosnd_pcm_stream_fn, stream, "vpcm%u",
				     substream->stream);
	if (IS_ERR(stream->thread)) {
		code = PTR_ERR(stream->thread);
		stream->thread = NULL;
		return code;
	}

	sched_setscheduler(stream->thread, SCHED_FIFO, &sched_params);

	substream->runtime->hw = stream->hw;

	if (stream->period_size_list.count > 0)
		snd_pcm_hw_constraint_list(substream->runtime, 0,
					   SNDRV_PCM_HW_PARAM_PERIOD_SIZE,
					   &stream->period_size_list);

	return 0;
}

static int viosnd_pcm_close(struct snd_pcm_substream *substream)
{
	struct viosnd_pcm_stream *stream = viosnd_pcm_substream_ctx(substream);

	if (!stream)
		return -EBADFD;

	if (stream->thread)
		kthread_stop(stream->thread);

	return 0;
}

static int viosnd_pcm_hw_params(struct snd_pcm_substream *substream,
				struct snd_pcm_hw_params *hw_params)
{
	static const struct {
		unsigned int alsa_fmt;
		unsigned int vio_fmt;
	} fmtmap[] = {
		{ SNDRV_PCM_FORMAT_S8, VIRTIO_SND_PCM_FMT_S8 },
		{ SNDRV_PCM_FORMAT_U8, VIRTIO_SND_PCM_FMT_U8 },
		{ SNDRV_PCM_FORMAT_S16, VIRTIO_SND_PCM_FMT_S16 },
		{ SNDRV_PCM_FORMAT_U16, VIRTIO_SND_PCM_FMT_U16 },
		{ SNDRV_PCM_FORMAT_S24, VIRTIO_SND_PCM_FMT_S24 },
		{ SNDRV_PCM_FORMAT_U24, VIRTIO_SND_PCM_FMT_U24 },
		{ SNDRV_PCM_FORMAT_S32, VIRTIO_SND_PCM_FMT_S32 },
		{ SNDRV_PCM_FORMAT_U32, VIRTIO_SND_PCM_FMT_U32 },
		{ SNDRV_PCM_FORMAT_FLOAT, VIRTIO_SND_PCM_FMT_FLOAT },
		{ SNDRV_PCM_FORMAT_FLOAT64, VIRTIO_SND_PCM_FMT_FLOAT64 },
		{ SNDRV_PCM_FORMAT_S20, VIRTIO_SND_PCM_FMT_S20 },
		{ SNDRV_PCM_FORMAT_U20, VIRTIO_SND_PCM_FMT_U20 },
		{ SNDRV_PCM_FORMAT_S24_3, VIRTIO_SND_PCM_FMT_S24_3 },
		{ SNDRV_PCM_FORMAT_U24_3, VIRTIO_SND_PCM_FMT_U24_3 },
		{ SNDRV_PCM_FORMAT_S20_3, VIRTIO_SND_PCM_FMT_S20_3 },
		{ SNDRV_PCM_FORMAT_U20_3, VIRTIO_SND_PCM_FMT_U20_3 },
		{ SNDRV_PCM_FORMAT_S18_3, VIRTIO_SND_PCM_FMT_S18_3 },
		{ SNDRV_PCM_FORMAT_U18_3, VIRTIO_SND_PCM_FMT_U18_3 }
	};

	static const struct {
		unsigned int rate;
		unsigned int vio_rate;
	} ratemap[] = {
		{ 8000, VIRTIO_SND_PCM_RATE_8000 },
		{ 11025, VIRTIO_SND_PCM_RATE_11025 },
		{ 16000, VIRTIO_SND_PCM_RATE_16000 },
		{ 22050, VIRTIO_SND_PCM_RATE_22050 },
		{ 32000, VIRTIO_SND_PCM_RATE_32000 },
		{ 44100, VIRTIO_SND_PCM_RATE_44100 },
		{ 48000, VIRTIO_SND_PCM_RATE_48000 },
		{ 64000, VIRTIO_SND_PCM_RATE_64000 },
		{ 88200, VIRTIO_SND_PCM_RATE_88200 },
		{ 96000, VIRTIO_SND_PCM_RATE_96000 },
		{ 176400, VIRTIO_SND_PCM_RATE_176400 },
		{ 192000, VIRTIO_SND_PCM_RATE_192000 }
	};

	int code;
	struct viosnd_pcm_stream *stream = viosnd_pcm_substream_ctx(substream);
	struct viosnd_ctx *ctx;
	struct virtio_device *vdev;
	snd_pcm_format_t format;
	unsigned int channels;
	unsigned int rate;
	unsigned int buffer_size;
	struct viosnd_msg *msg;
	struct virtio_snd_pcm_set_format *request;
	int i;

	if (!stream)
		return -EBADFD;

	ctx = stream->pcm->ctx;
	vdev = ctx->vdev;

	format = params_format(hw_params);
	channels = snd_pcm_hw_param_value(hw_params,
					  SNDRV_PCM_HW_PARAM_CHANNELS, NULL);
	rate = snd_pcm_hw_param_value(hw_params,
				      SNDRV_PCM_HW_PARAM_RATE, NULL);
	buffer_size = snd_pcm_hw_param_value(hw_params,
					     SNDRV_PCM_HW_PARAM_BUFFER_BYTES,
					     NULL);

	msg = viosnd_ctl_msg_get(ctx, sizeof(*request),
				 sizeof(struct virtio_snd_hdr), GFP_KERNEL,
				 1000);
	if (IS_ERR(msg))
		return PTR_ERR(msg);

	request = (struct virtio_snd_pcm_set_format *)msg->request;

	viosnd_pcm_set_hdr(&request->hdr, stream, VIRTIO_SND_R_PCM_SET_FORMAT);
	request->channels = cpu_to_virtio16(vdev, channels);
	request->format = (u16)-1;
	request->rate = (u16)-1;

	for (i = 0; i < ARRAY_SIZE(fmtmap); ++i) {
		if (fmtmap[i].alsa_fmt == format) {
			request->format =
				cpu_to_virtio16(vdev, fmtmap[i].vio_fmt);

			break;
		}
	}

	for (i = 0; i < ARRAY_SIZE(ratemap); ++i) {
		if (ratemap[i].rate == rate) {
			request->rate =
				cpu_to_virtio16(vdev, ratemap[i].vio_rate);

			break;
		}
	}

	if ((request->format == (u16)-1) || (request->rate == (u16)-1)) {
		code = -EINVAL;
		goto on_failure;
	}

	code = viosnd_ctl_msg_send(ctx, msg, 1000);
	if (code != 0)
		goto on_failure;

	substream->runtime->dma_area = stream->data;
	substream->runtime->dma_bytes = buffer_size;

on_failure:
	viosnd_ctl_msg_put(ctx, msg);

	return code;
}

static int viosnd_pcm_hw_free(struct snd_pcm_substream *substream)
{
	int code;
	struct viosnd_pcm_stream *stream = viosnd_pcm_substream_ctx(substream);

	if (!stream)
		return -EBADFD;

	substream->runtime->dma_area = NULL;
	substream->runtime->dma_bytes = 0;

	return code;
}

static int viosnd_pcm_prepare(struct snd_pcm_substream *substream)
{
	struct viosnd_pcm_stream *stream = viosnd_pcm_substream_ctx(substream);
	unsigned long flags;
	unsigned long js = msecs_to_jiffies(2 * pcm_xfer_ms);

	if (!stream)
		return -EBADFD;

	spin_lock_irqsave(&stream->thread_lock, flags);
	wait_event_interruptible_lock_irq_timeout(stream->thread_wait_idle,
						  stream->thread_idle,
						  stream->thread_lock, js);
	spin_unlock_irqrestore(&stream->thread_lock, flags);

	return viosnd_pcm_send_generic(stream, VIRTIO_SND_R_PCM_PREPARE,
				       GFP_KERNEL, 1000);
}

static inline void viosnd_pcm_update_hw_ptr(struct viosnd_pcm_stream *stream,
					    u64 current_ns)
{
	struct snd_pcm_runtime *runtime = stream->substream->runtime;
	u64 elapsed_ns;
	u64 value;
	snd_pcm_sframes_t frames;

	elapsed_ns = current_ns - stream->hw_ptr.begin_ns;
	value = runtime->rate * elapsed_ns + stream->hw_ptr.carry_value;

	stream->hw_ptr.value += value / NSEC_PER_SEC;
	stream->hw_ptr.carry_value = value % NSEC_PER_SEC;
	stream->hw_ptr.begin_ns = current_ns;

	if (stream->hw_ptr.value >= runtime->boundary)
		stream->hw_ptr.value -= runtime->boundary;

	spin_lock(&stream->thread_lock);
	frames = viosnd_pcm_size(stream, stream->shadow.guest_position,
				 stream->hw_ptr.value);
	if (frames > 0)
		viosnd_pcm_copy_to_shadow(stream, frames);
	spin_unlock(&stream->thread_lock);
}

static void viosnd_pcm_ctl_notify_cb(struct viosnd_msg *msg)
{
	struct viosnd_pcm_stream *stream = msg->cb_data;
	u64 current_ns;
	u32 request_code = le32_to_cpu(msg->request->code);

	current_ns = ktime_get_raw_ns();

	switch (request_code) {
		case VIRTIO_SND_R_PCM_PAUSE: {
			spin_lock(&stream->thread_lock);
			stream->pause_ns = current_ns;
			spin_unlock(&stream->thread_lock);

			break;
		}
		case VIRTIO_SND_R_PCM_UNPAUSE: {
			spin_lock(&stream->thread_lock);
			stream->xfer_start_ns = current_ns;
			stream->thread_busy = true;
			wake_up(&stream->thread_wait_busy);
			spin_unlock(&stream->thread_lock);

			break;
		}
	}
}

static int viosnd_pcm_trigger(struct snd_pcm_substream *substream, int command)
{
	struct viosnd_pcm_stream *stream = viosnd_pcm_substream_ctx(substream);
	u64 current_ns;
	u32 request_code;

	if (!stream)
		return -EBADFD;

	current_ns = ktime_get_raw_ns();

	switch (command) {
	case SNDRV_PCM_TRIGGER_START: {
		stream->period_position = 0;
		stream->hw_ptr.value = 0;
		stream->hw_ptr.carry_value = 0;
		stream->shadow.host_position = 0;
		stream->shadow.guest_position = 0;

		if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
			snd_pcm_uframes_t prebuf_size =
				viosnd_pcm_period_size(stream) * 2;

			viosnd_pcm_copy_to_shadow(stream, prebuf_size);

			viosnd_pcm_xfer_write(stream, prebuf_size, GFP_ATOMIC);
		}

		/* fallthru */
	}
	case SNDRV_PCM_TRIGGER_PAUSE_RELEASE: {
		spin_lock(&stream->thread_lock);
		if (stream->hw_ptr.value < stream->shadow.guest_position)
			stream->hw_ptr.value = stream->shadow.guest_position;
		stream->hw_ptr.begin_ns = current_ns;

		if (command == SNDRV_PCM_TRIGGER_START) {
			request_code = VIRTIO_SND_R_PCM_START;

			stream->xfer_idle_size = viosnd_pcm_period_size(stream);
			stream->xfer_start_ns = current_ns;
			stream->xfer_carry_ns = 0;

			stream->thread_busy = true;
			wake_up(&stream->thread_wait_busy);
		} else {
			request_code = VIRTIO_SND_R_PCM_UNPAUSE;
		}
		spin_unlock(&stream->thread_lock);

		break;
	}
	case SNDRV_PCM_TRIGGER_STOP:
	case SNDRV_PCM_TRIGGER_PAUSE_PUSH: {
		spin_lock(&stream->thread_lock);
		stream->thread_busy = false;
		spin_unlock(&stream->thread_lock);

		if (command == SNDRV_PCM_TRIGGER_STOP) {
			request_code = VIRTIO_SND_R_PCM_STOP;
		} else {
			request_code = VIRTIO_SND_R_PCM_PAUSE;

			viosnd_pcm_update_hw_ptr(stream, current_ns);
		}

		break;
	}
	default: {
		return 0;
	}
	}

	return viosnd_pcm_send_generic_cb(stream, request_code, GFP_ATOMIC, 0,
					  viosnd_pcm_ctl_notify_cb);
}

static snd_pcm_uframes_t viosnd_pcm_pointer(struct snd_pcm_substream *substream)
{
	struct viosnd_pcm_stream *stream = viosnd_pcm_substream_ctx(substream);
	struct snd_pcm_runtime *runtime = substream->runtime;

	if (!stream)
		return 0;

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
		if (snd_pcm_running(substream))
			viosnd_pcm_update_hw_ptr(stream, ktime_get_raw_ns());

	return stream->hw_ptr.value % runtime->buffer_size;
}

static int viosnd_pcm_mmap(struct snd_pcm_substream *substream,
			   struct vm_area_struct *vma)
{
	struct viosnd_pcm_stream *stream = viosnd_pcm_substream_ctx(substream);

	if (!stream)
		return -EBADFD;

	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;

	return remap_pfn_range(vma, vma->vm_start,
			       virt_to_phys(stream->data) >> PAGE_SHIFT,
			       vma->vm_end - vma->vm_start, vma->vm_page_prot);
}

static const struct snd_pcm_ops viosnd_pcm_ops = {
	.open = viosnd_pcm_open,
	.close = viosnd_pcm_close,
	.ioctl = snd_pcm_lib_ioctl,
	.hw_params = viosnd_pcm_hw_params,
	.hw_free = viosnd_pcm_hw_free,
	.prepare = viosnd_pcm_prepare,
	.trigger = viosnd_pcm_trigger,
	.pointer = viosnd_pcm_pointer,
	.mmap = viosnd_pcm_mmap
};

static int viosnd_pcm_chmap_configure(struct viosnd_pcm_stream *stream)
{
	static const u8 positions[] = {
		[VIRTIO_SND_PCM_CH_NONE] = SNDRV_CHMAP_UNKNOWN,
		[VIRTIO_SND_PCM_CH_NA] = SNDRV_CHMAP_NA,
		[VIRTIO_SND_PCM_CH_MONO] = SNDRV_CHMAP_MONO,
		[VIRTIO_SND_PCM_CH_FL] = SNDRV_CHMAP_FL,
		[VIRTIO_SND_PCM_CH_FR] = SNDRV_CHMAP_FR,
		[VIRTIO_SND_PCM_CH_RL] = SNDRV_CHMAP_RL,
		[VIRTIO_SND_PCM_CH_RR] = SNDRV_CHMAP_RR,
		[VIRTIO_SND_PCM_CH_FC] = SNDRV_CHMAP_FC,
		[VIRTIO_SND_PCM_CH_LFE] = SNDRV_CHMAP_LFE,
		[VIRTIO_SND_PCM_CH_SL] = SNDRV_CHMAP_SL,
		[VIRTIO_SND_PCM_CH_SR] = SNDRV_CHMAP_SR,
		[VIRTIO_SND_PCM_CH_RC] = SNDRV_CHMAP_RC,
		[VIRTIO_SND_PCM_CH_FLC] = SNDRV_CHMAP_FLC,
		[VIRTIO_SND_PCM_CH_FRC] = SNDRV_CHMAP_FRC,
		[VIRTIO_SND_PCM_CH_RLC] = SNDRV_CHMAP_RLC,
		[VIRTIO_SND_PCM_CH_RRC] = SNDRV_CHMAP_RRC,
		[VIRTIO_SND_PCM_CH_FLW] = SNDRV_CHMAP_FLW,
		[VIRTIO_SND_PCM_CH_FRW] = SNDRV_CHMAP_FRW,
		[VIRTIO_SND_PCM_CH_FLH] = SNDRV_CHMAP_FLH,
		[VIRTIO_SND_PCM_CH_FCH] = SNDRV_CHMAP_FCH,
		[VIRTIO_SND_PCM_CH_FRH] = SNDRV_CHMAP_FRH,
		[VIRTIO_SND_PCM_CH_TC] = SNDRV_CHMAP_TC,
		[VIRTIO_SND_PCM_CH_TFL] = SNDRV_CHMAP_TFL,
		[VIRTIO_SND_PCM_CH_TFR] = SNDRV_CHMAP_TFR,
		[VIRTIO_SND_PCM_CH_TFC] = SNDRV_CHMAP_TFC,
		[VIRTIO_SND_PCM_CH_TRL] = SNDRV_CHMAP_TRL,
		[VIRTIO_SND_PCM_CH_TRR] = SNDRV_CHMAP_TRR,
		[VIRTIO_SND_PCM_CH_TRC] = SNDRV_CHMAP_TRC,
		[VIRTIO_SND_PCM_CH_TFLC] = SNDRV_CHMAP_TFLC,
		[VIRTIO_SND_PCM_CH_TFRC] = SNDRV_CHMAP_TFRC,
		[VIRTIO_SND_PCM_CH_TSL] = SNDRV_CHMAP_TSL,
		[VIRTIO_SND_PCM_CH_TSR] = SNDRV_CHMAP_TSR,
		[VIRTIO_SND_PCM_CH_LLFE] = SNDRV_CHMAP_LLFE,
		[VIRTIO_SND_PCM_CH_RLFE] = SNDRV_CHMAP_RLFE,
		[VIRTIO_SND_PCM_CH_BC] = SNDRV_CHMAP_BC,
		[VIRTIO_SND_PCM_CH_BLC] = SNDRV_CHMAP_BLC,
		[VIRTIO_SND_PCM_CH_BRC] = SNDRV_CHMAP_BRC
	};

	int code;
	struct viosnd_ctx *ctx = stream->pcm->ctx;
	struct virtio_device *vdev = ctx->vdev;
	struct device *dev = &vdev->dev;
	struct snd_pcm_chmap_elem *chmaps;
	struct viosnd_msg *msg;
	struct virtio_snd_pcm_query_chmap *request;
	struct virtio_snd_pcm_chmap_info *response;
	u8 chmap_id;

	chmaps = devm_kzalloc(dev, sizeof(*chmaps) * (stream->nchmaps + 1),
			      GFP_KERNEL);
	if (!chmaps)
		return -ENOMEM;

	msg = viosnd_ctl_msg_get(ctx, sizeof(*request), sizeof(*response),
				 GFP_KERNEL, 1000);
	if (IS_ERR(msg))
		return PTR_ERR(msg);

	request = (struct virtio_snd_pcm_query_chmap *)msg->request;

	request->hdr.code = cpu_to_virtio32(vdev, VIRTIO_SND_R_PCM_QUERY_CHMAP);
	request->pcm_id = stream->pcm->pcm->device;
	request->stream_type =
		(stream->substream->stream == SNDRV_PCM_STREAM_PLAYBACK) ?
			VIRTIO_SND_PCM_T_PLAYBACK :
			VIRTIO_SND_PCM_T_CAPTURE;

	response = (struct virtio_snd_pcm_chmap_info *)msg->response;

	for (chmap_id = 0; chmap_id < stream->nchmaps; ++chmap_id) {
		struct snd_pcm_chmap_elem *chmap = chmaps + chmap_id;
		u16 nchannels;
		u16 i;

		request->chmap_id = chmap_id;

		memset(response, 0, sizeof(*response));

		code = viosnd_ctl_msg_send(ctx, msg, 1000);
		if (code)
			goto on_failure;

		switch (response->type) {
		case VIRTIO_SND_PCM_CHMAP_FIXED:
		case VIRTIO_SND_PCM_CHMAP_VARIABLE:
		case VIRTIO_SND_PCM_CHMAP_PAIRED:
		{
			nchannels = le16_to_cpu(response->nchannels);
			if (nchannels > ARRAY_SIZE(chmap->map))
				nchannels = ARRAY_SIZE(chmap->map);

			chmap->channels = nchannels;

			break;
		}
		default:
		{
			code = -EINVAL;
			goto on_failure;
		}
		}

		for (i = 0; i < nchannels; ++i) {
			u8 position = response->positions[i];

			if (position > ARRAY_SIZE(positions)) {
				code = -EINVAL;
				goto on_failure;
			}

			chmap->map[i] = positions[position];
		}
	}

	code = snd_pcm_add_chmap_ctls(stream->pcm->pcm,
				      stream->substream->stream, chmaps,
				      stream->hw.channels_max, 0, NULL);

on_failure:
	viosnd_ctl_msg_put(ctx, msg);

	return code;
}

static struct viosnd_pcm_stream *
viosnd_pcm_stream_configure(struct viosnd_pcm *pcm,
			    struct virtio_snd_pcm_stream_desc *desc)
{
	static const struct {
		u32 vio_bit;
		unsigned int alsa_fmt;
	} fmtmap[] = {
		{ VIRTIO_SND_PCM_FMTBIT_S8, SNDRV_PCM_FORMAT_S8 },
		{ VIRTIO_SND_PCM_FMTBIT_U8, SNDRV_PCM_FORMAT_U8 },
		{ VIRTIO_SND_PCM_FMTBIT_S16, SNDRV_PCM_FORMAT_S16 },
		{ VIRTIO_SND_PCM_FMTBIT_U16, SNDRV_PCM_FORMAT_U16 },
		{ VIRTIO_SND_PCM_FMTBIT_S24, SNDRV_PCM_FORMAT_S24 },
		{ VIRTIO_SND_PCM_FMTBIT_U24, SNDRV_PCM_FORMAT_U24 },
		{ VIRTIO_SND_PCM_FMTBIT_S32, SNDRV_PCM_FORMAT_S32 },
		{ VIRTIO_SND_PCM_FMTBIT_U32, SNDRV_PCM_FORMAT_U32 },
		{ VIRTIO_SND_PCM_FMTBIT_FLOAT, SNDRV_PCM_FORMAT_FLOAT },
		{ VIRTIO_SND_PCM_FMTBIT_FLOAT64, SNDRV_PCM_FORMAT_FLOAT64 },
		{ VIRTIO_SND_PCM_FMTBIT_S20, SNDRV_PCM_FORMAT_S20 },
		{ VIRTIO_SND_PCM_FMTBIT_U20, SNDRV_PCM_FORMAT_U20 },
		{ VIRTIO_SND_PCM_FMTBIT_S24_3, SNDRV_PCM_FORMAT_S24_3 },
		{ VIRTIO_SND_PCM_FMTBIT_U24_3, SNDRV_PCM_FORMAT_U24_3 },
		{ VIRTIO_SND_PCM_FMTBIT_S20_3, SNDRV_PCM_FORMAT_S20_3 },
		{ VIRTIO_SND_PCM_FMTBIT_U20_3, SNDRV_PCM_FORMAT_U20_3 },
		{ VIRTIO_SND_PCM_FMTBIT_S18_3, SNDRV_PCM_FORMAT_S18_3 },
		{ VIRTIO_SND_PCM_FMTBIT_U18_3, SNDRV_PCM_FORMAT_U18_3 }
	};

	static const struct {
		u32 vio_bit;
		u64 alsa_bit;
		unsigned int rate;
	} ratemap[] = {
		{ VIRTIO_SND_PCM_RATEBIT_8000, SNDRV_PCM_RATE_8000, 8000 },
		{ VIRTIO_SND_PCM_RATEBIT_11025, SNDRV_PCM_RATE_11025, 11025 },
		{ VIRTIO_SND_PCM_RATEBIT_16000, SNDRV_PCM_RATE_16000, 16000 },
		{ VIRTIO_SND_PCM_RATEBIT_22050, SNDRV_PCM_RATE_22050, 22050 },
		{ VIRTIO_SND_PCM_RATEBIT_32000, SNDRV_PCM_RATE_32000, 32000 },
		{ VIRTIO_SND_PCM_RATEBIT_44100, SNDRV_PCM_RATE_44100, 44100 },
		{ VIRTIO_SND_PCM_RATEBIT_48000, SNDRV_PCM_RATE_48000, 48000 },
		{ VIRTIO_SND_PCM_RATEBIT_64000, SNDRV_PCM_RATE_64000, 64000 },
		{ VIRTIO_SND_PCM_RATEBIT_88200, SNDRV_PCM_RATE_88200, 88200 },
		{ VIRTIO_SND_PCM_RATEBIT_96000, SNDRV_PCM_RATE_96000, 96000 },
		{ VIRTIO_SND_PCM_RATEBIT_176400, SNDRV_PCM_RATE_176400,
		  176400 },
		{ VIRTIO_SND_PCM_RATEBIT_192000, SNDRV_PCM_RATE_192000, 192000 }
	};

	struct device *dev = &pcm->ctx->vdev->dev;
	struct viosnd_pcm_stream *stream;
	unsigned int i;
	u32 formats;
	u32 rates;
	u32 sample_size_min = 0;
	u32 sample_size_max = 0;
	unsigned int page_order;

	stream = devm_kzalloc(dev, sizeof(*stream), GFP_KERNEL);
	if (!stream)
		return ERR_PTR(-ENOMEM);

	stream->pcm = pcm;
	stream->nchmaps = desc->nchmaps;
	spin_lock_init(&stream->thread_lock);
	init_waitqueue_head(&stream->thread_wait_idle);
	init_waitqueue_head(&stream->thread_wait_busy);

	stream->hw.info =
		SNDRV_PCM_INFO_MMAP | SNDRV_PCM_INFO_MMAP_VALID |
		SNDRV_PCM_INFO_INTERLEAVED | SNDRV_PCM_INFO_BLOCK_TRANSFER |
		/*SNDRV_PCM_INFO_RESUME |*/
		SNDRV_PCM_INFO_PAUSE | SNDRV_PCM_INFO_NO_PERIOD_WAKEUP;

	formats = le32_to_cpu(desc->formats);

	for (i = 0; i < ARRAY_SIZE(fmtmap); ++i) {
		if (formats & fmtmap[i].vio_bit) {
			unsigned int alsa_fmt = fmtmap[i].alsa_fmt;
			int size = snd_pcm_format_physical_width(alsa_fmt) / 8;

			if (!sample_size_min || sample_size_min > size)
				sample_size_min = size;

			if (sample_size_max < size)
				sample_size_max = size;

			stream->hw.formats |= (1ULL << alsa_fmt);
		}
	}

	if (!stream->hw.formats) {
		dev_err(dev, "No supported formats found");
		return ERR_PTR(-EINVAL);
	}

	rates = le32_to_cpu(desc->rates);

	for (i = 0; i < ARRAY_SIZE(ratemap); ++i) {
		if (rates & ratemap[i].vio_bit) {
			if (stream->hw.rate_min == 0 ||
			    stream->hw.rate_min > ratemap[i].rate)
				stream->hw.rate_min = ratemap[i].rate;

			if (stream->hw.rate_max < ratemap[i].rate)
				stream->hw.rate_max = ratemap[i].rate;

			stream->hw.rates |= ratemap[i].alsa_bit;
		}
	}

	if (!stream->hw.rates) {
		dev_err(dev, "No supported rates found");
		return ERR_PTR(-EINVAL);
	}

	stream->hw.period_bytes_min =
		(sample_size_min * desc->channels_min * desc->period_size_min);
	stream->hw.period_bytes_max =
		(sample_size_max * desc->channels_max * desc->period_size_max);
	stream->hw.channels_min = desc->channels_min;
	stream->hw.channels_max = desc->channels_max;
	stream->hw.periods_min = 2;
	stream->hw.periods_max = 16;
	stream->hw.buffer_bytes_max =
		stream->hw.periods_max * stream->hw.period_bytes_max;

	if (desc->period_size_list_count > 0) {
		const size_t size = sizeof(desc->period_size_list[0]) *
				desc->period_size_list_count;
		unsigned int* const elems = devm_kzalloc(dev, size, GFP_KERNEL);

		if (!elems)
			return ERR_PTR(-ENOMEM);
		for (i = 0; i < desc->period_size_list_count; ++i)
			elems[i] = desc->period_size_list[i];

		stream->period_size_list.count = desc->period_size_list_count;
		stream->period_size_list.list = elems;
	}

	page_order = get_order(stream->hw.buffer_bytes_max);

	stream->data = (void *)devm_get_free_pages(dev, GFP_KERNEL, page_order);
	if (!stream->data)
		return ERR_PTR(-ENOMEM);

	if (desc->stream_type == VIRTIO_SND_PCM_T_PLAYBACK) {
		stream->shadow.data =
			(void *)devm_get_free_pages(dev, GFP_KERNEL,
						    page_order);
		if (!stream->shadow.data)
			return ERR_PTR(-ENOMEM);
	}

	return stream;
}

static int viosnd_pcm_configure(struct viosnd_ctx *ctx,
				struct virtio_snd_pcm_desc *desc)
{
	static int typemap[] = {
		[VIRTIO_SND_PCM_T_PLAYBACK] = SNDRV_PCM_STREAM_PLAYBACK,
		[VIRTIO_SND_PCM_T_CAPTURE] = SNDRV_PCM_STREAM_CAPTURE
	};
	int code;
	struct device *dev = &ctx->vdev->dev;
	struct viosnd_pcm *pcm;
	struct virtio_snd_pcm_stream_desc *stream_desc;
	unsigned int i;
	unsigned int npbs = 0;
	unsigned int ncps = 0;
	unsigned int queue_id;
	struct viosnd_msg *msg;
	struct virtio_snd_pcm_set_queue *request;

	if (desc->length != sizeof(struct virtio_snd_pcm_desc))
		return -EINVAL;

	pcm = devm_kzalloc(dev, sizeof(*pcm), GFP_KERNEL);
	if (!pcm)
		return -ENOMEM;

	pcm->ctx = ctx;

	stream_desc = (struct virtio_snd_pcm_stream_desc *)(desc + 1);

	for (i = 0; i < desc->nstreams; i++, stream_desc++) {
		bool valid =
			(stream_desc->type == VIRTIO_SND_DESC_PCM_STREAM) &&
			(stream_desc->length ==
			 sizeof(struct virtio_snd_pcm_stream_desc)) &&
			((stream_desc->stream_type ==
			  VIRTIO_SND_PCM_T_PLAYBACK) ||
			 (stream_desc->stream_type ==
			  VIRTIO_SND_PCM_T_CAPTURE)) &&
			!pcm->streams[stream_desc->stream_type];

		if (!valid) {
			dev_err(dev, "Malformed PCM stream configuration");
			return -EINVAL;
		}

		pcm->streams[stream_desc->stream_type] =
			viosnd_pcm_stream_configure(pcm, stream_desc);
		if (IS_ERR(pcm->streams[stream_desc->stream_type]))
			return PTR_ERR(pcm->streams[stream_desc->stream_type]);
	}

	if (pcm->streams[VIRTIO_SND_PCM_T_PLAYBACK])
		npbs = 1;

	if (pcm->streams[VIRTIO_SND_PCM_T_CAPTURE])
		ncps = 1;

	if (!npbs && !ncps) {
		dev_err(dev, "No PCM stream found");
		return -EINVAL;
	}

	pcm->queue = viosnd_queue_assign(ctx, viosnd_pcm_notify_cb, pcm);
	if (IS_ERR(pcm->queue)) {
		dev_err(dev, "Could not assign PCM data queue");
		return PTR_ERR(pcm->queue);
	}

	spin_lock_init(&pcm->lock);
	pcm->msg_count = virtqueue_get_vring_size(pcm->queue) / 2;

	msg = viosnd_ctl_msg_get(ctx, sizeof(*request),
				 sizeof(struct virtio_snd_hdr), GFP_KERNEL,
				 1000);
	if (IS_ERR(msg))
		return PTR_ERR(msg);

	request = (struct virtio_snd_pcm_set_queue *)msg->request;

	request->hdr.code =
		cpu_to_virtio32(ctx->vdev, VIRTIO_SND_R_PCM_SET_QUEUE);
	request->pcm_id = desc->pcm_id;

	for (queue_id = 0; queue_id < ctx->queue_count; ++queue_id)
		if (pcm->queue == ctx->queues[queue_id].queue) {
			request->queue = cpu_to_virtio32(ctx->vdev, queue_id);

			break;
		}

	code = viosnd_ctl_msg_send(ctx, msg, 1000);
	if (code) {
		dev_err(dev, "Could not set PCM data queue: %d", code);
		goto on_failure;
	}

	code = snd_pcm_new(ctx->card, "virtio_snd", desc->pcm_id, npbs, ncps,
			   &pcm->pcm);
	if (code) {
		dev_err(dev, "snd_pcm_new failed: %d", code);
		goto on_failure;
	}

	pcm->pcm->info_flags = 0;
	pcm->pcm->dev_class = SNDRV_PCM_CLASS_GENERIC;
	pcm->pcm->dev_subclass = SNDRV_PCM_SUBCLASS_GENERIC_MIX;
	strcpy(pcm->pcm->name, "VirtIO Sound Card PCM");
	pcm->pcm->private_data = pcm;

	for (i = 0; i < ARRAY_SIZE(typemap); ++i) {
		struct viosnd_pcm_stream *stream = pcm->streams[i];

		if (!stream)
			continue;

		snd_pcm_set_ops(pcm->pcm, typemap[i], &viosnd_pcm_ops);

		stream->substream = pcm->pcm->streams[typemap[i]].substream;

		if (stream->nchmaps) {
			if (viosnd_pcm_chmap_configure(stream)) {
				dev_err(dev, "Failed to configure channel map");
				return -EINVAL;
			}
		}
	}

on_failure:
	viosnd_ctl_msg_put(ctx, msg);

	if (code)
		return code; /* failure */

	return sizeof(struct virtio_snd_pcm_desc) +
	       sizeof(struct virtio_snd_pcm_stream_desc) * desc->nstreams;
}

static int viosnd_card_configure(struct viosnd_ctx *ctx)
{
	static int g_ndevices;
	static int g_indexes[SNDRV_CARDS] = SNDRV_DEFAULT_IDX;
	static char *g_ids[SNDRV_CARDS] = SNDRV_DEFAULT_STR;
	static struct snd_device_ops ops = { 0 };

	int code;
	struct virtio_device *vdev = ctx->vdev;
	struct device *dev = &vdev->dev;
	struct viosnd_msg *msg;
	struct virtio_snd_base_configuration *response;
	u32 data_length;
	u8 *data;

	if (g_ndevices >= SNDRV_CARDS)
		return -ENODEV;

	msg = viosnd_ctl_msg_get(ctx, sizeof(struct virtio_snd_hdr),
				 sizeof(*response), GFP_KERNEL, 1000);
	if (IS_ERR(msg))
		return PTR_ERR(msg);

	msg->request->code = cpu_to_virtio32(vdev, VIRTIO_SND_R_BASE_GET_CFG);

	code = viosnd_ctl_msg_send(ctx, msg, 1000);
	if (code != 0) {
		dev_err(dev, "Could not get device configuration: %d", code);
		goto on_failure;
	}

	code = snd_card_new(dev, g_indexes[g_ndevices], g_ids[g_ndevices],
			    THIS_MODULE, 0, &ctx->card);
	if (code < 0)
		goto on_failure;

	strlcpy(ctx->card->id, "viosnd", sizeof(ctx->card->id));
	strlcpy(ctx->card->driver, "virtio_snd", sizeof(ctx->card->driver));
	strlcpy(ctx->card->shortname, "VIOSND", sizeof(ctx->card->shortname));
	strlcpy(ctx->card->longname, "VirtIO Sound Card",
		sizeof(ctx->card->longname));
	ctx->card->private_data = ctx;

	code = snd_device_new(ctx->card, SNDRV_DEV_LOWLEVEL, ctx, &ops);
	if (code < 0)
		goto on_failure;

	response = (struct virtio_snd_base_configuration *)msg->response;

	data_length = response->length;
	data = response->data;

	while (data_length != 0) {
		struct virtio_snd_desc *desc = (struct virtio_snd_desc *)data;
		u32 desc_length;

		switch (desc->type) {
		case VIRTIO_SND_DESC_PCM: {
			struct virtio_snd_pcm_desc *pcm_desc =
				(struct virtio_snd_pcm_desc *)desc;

			code = viosnd_pcm_configure(ctx, pcm_desc);
			if (code < 0)
				goto on_failure;

			desc_length = code;

			break;
		}
		default: {
			desc_length = desc->length;

			break;
		}
		}

		if (desc_length > data_length)
			desc_length = data_length;

		data_length -= desc_length;
		data += desc_length;
	}

	code = snd_card_register(ctx->card);
	if (code < 0)
		goto on_failure;

	g_ndevices++;

	code = 0; /* success */

on_failure:
	viosnd_ctl_msg_put(ctx, msg);

	return code;
}

static int viosnd_probe(struct virtio_device *vdev)
{
	int code;
	struct device *dev = &vdev->dev;
	struct viosnd_ctx *ctx;
	unsigned int i;
	struct virtqueue **queues = NULL;
	vq_callback_t **callbacks = NULL;
	const char **names = NULL;
	struct irq_affinity affinity = {
		0,
	};

	if (!vdev->config->get) {
		dev_err(dev, "Config access disabled");
		return -EINVAL;
	}

	ctx = devm_kzalloc(dev, sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->vdev = vdev;
	vdev->priv = ctx;

	virtio_cread(vdev, struct virtio_snd_config, nqueues,
		     &ctx->queue_max_count);

	if (ctx->queue_max_count == 0 || ctx->queue_max_count > 255) {
		dev_err(dev, "Invalid number of virtual queues: %u",
			ctx->queue_max_count);
		return -EINVAL;
	}

	ctx->queues =
		devm_kzalloc(dev,
			     sizeof(*ctx->queues) * ctx->queue_max_count,
			     GFP_KERNEL);
	if (!ctx->queues)
		return -ENOMEM;

	queues = devm_kzalloc(dev, sizeof(void *) * ctx->queue_max_count,
			      GFP_KERNEL);
	if (!queues)
		return -ENOMEM;

	callbacks = devm_kzalloc(dev, sizeof(void *) * ctx->queue_max_count,
				 GFP_KERNEL);
	if (!callbacks)
		return -ENOMEM;

	names = devm_kzalloc(dev, sizeof(void *) * ctx->queue_max_count,
			     GFP_KERNEL);
	if (!names)
		return -ENOMEM;

	for (i = 0; i < ctx->queue_max_count; ++i) {
		callbacks[i] = viosnd_notify_cb;
		names[i] = "viosnd";
	}

	code = virtio_find_vqs(vdev, ctx->queue_max_count, queues, callbacks,
			       names, &affinity);
	if (code != 0)
		return code;

	for (i = 0; i < ctx->queue_max_count; ++i) {
		ctx->queues[i].queue = queues[i];
		virtqueue_disable_cb(queues[i]);
	}

	devm_kfree(dev, callbacks);
	devm_kfree(dev, names);

	ctx->ctl_queue = viosnd_queue_assign(ctx, viosnd_ctl_notify_cb, ctx);
	if (IS_ERR(ctx->ctl_queue))
		return PTR_ERR(ctx->ctl_queue);

	ctx->msg_count = virtqueue_get_vring_size(ctx->ctl_queue) / 2;

	spin_lock_init(&ctx->lock);
	init_waitqueue_head(&ctx->wait_available);

	virtio_device_ready(vdev);

	return viosnd_card_configure(ctx);
}

static void viosnd_remove(struct virtio_device *vdev)
{
	struct viosnd_ctx *ctx = vdev->priv;

	if (!ctx)
		return;

	if (ctx->card)
		snd_card_free(ctx->card);

	vdev->config->reset(vdev);
	vdev->config->del_vqs(vdev);

	vdev->priv = NULL;
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_SOUND, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver viosnd_driver = {
	.driver.name = KBUILD_MODNAME,
	.driver.owner = THIS_MODULE,
	.id_table = id_table,
	.probe = viosnd_probe,
	.remove = viosnd_remove,
/* TODO: device power management */
#ifdef CONFIG_PM_SLEEP
	.freeze = NULL,
	.restore = NULL,
#endif
};

static int __init init(void)
{
	return register_virtio_driver(&viosnd_driver);
}
module_init(init);

static void __exit fini(void)
{
	unregister_virtio_driver(&viosnd_driver);
}
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio sound card driver");
MODULE_LICENSE("GPL");
