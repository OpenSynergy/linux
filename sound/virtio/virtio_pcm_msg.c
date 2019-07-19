// SPDX-License-Identifier: GPL-2.0+
/*
 * Sound card driver for virtio
 * Copyright (C) 2020  OpenSynergy GmbH
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
#include <sound/pcm_params.h>

#include "virtio_pcm.h"

/**
 * enum pcm_msg_sg_index - Scatter-gather element indexes for an I/O message
 * @PCM_MSG_SG_XFER: Element containing a virtio_snd_pcm_xfer structure
 * @PCM_MSG_SG_DATA: Element containing a data buffer
 * @PCM_MSG_SG_STATUS: Element containing a virtio_snd_pcm_status structure
 * @PCM_MSG_SG_MAX: The maximum number of elements in the scatter-gather table
 */
enum pcm_msg_sg_index {
	PCM_MSG_SG_XFER = 0,
	PCM_MSG_SG_DATA,
	PCM_MSG_SG_STATUS,
	PCM_MSG_SG_MAX
};

/**
 * struct virtio_pcm_msg - I/O message representation
 * @list: Pending I/O message list entry
 * @substream: Virtio PCM substream
 * @xfer: I/O message header payload
 * @status: I/O message status payload
 * @one_shot_data: if the message should not be resent to the device, the field
 *                 contains a pointer to the optional payload that should be
 *                 released after completion
 * @sgs: I/O message scatter-gather table
 */
struct virtio_pcm_msg {
	struct list_head list;
	struct virtio_pcm_substream *substream;
	struct virtio_snd_pcm_xfer xfer;
	struct virtio_snd_pcm_status status;
	void *one_shot_data;
	struct scatterlist sgs[PCM_MSG_SG_MAX];
};

struct virtsnd_a2v_format {
	unsigned int alsa_bit;
	unsigned int vio_bit;
};

static const struct virtsnd_a2v_format g_a2v_format_map[] = {
	{ SNDRV_PCM_FORMAT_IMA_ADPCM, VIRTIO_SND_PCM_FMT_IMA_ADPCM },
	{ SNDRV_PCM_FORMAT_MU_LAW, VIRTIO_SND_PCM_FMT_MU_LAW },
	{ SNDRV_PCM_FORMAT_A_LAW, VIRTIO_SND_PCM_FMT_A_LAW },
	{ SNDRV_PCM_FORMAT_S8, VIRTIO_SND_PCM_FMT_S8 },
	{ SNDRV_PCM_FORMAT_U8, VIRTIO_SND_PCM_FMT_U8 },
	{ SNDRV_PCM_FORMAT_S16_LE, VIRTIO_SND_PCM_FMT_S16 },
	{ SNDRV_PCM_FORMAT_U16_LE, VIRTIO_SND_PCM_FMT_U16 },
	{ SNDRV_PCM_FORMAT_S18_3LE, VIRTIO_SND_PCM_FMT_S18_3 },
	{ SNDRV_PCM_FORMAT_U18_3LE, VIRTIO_SND_PCM_FMT_U18_3 },
	{ SNDRV_PCM_FORMAT_S20_3LE, VIRTIO_SND_PCM_FMT_S20_3 },
	{ SNDRV_PCM_FORMAT_U20_3LE, VIRTIO_SND_PCM_FMT_U20_3 },
	{ SNDRV_PCM_FORMAT_S24_3LE, VIRTIO_SND_PCM_FMT_S24_3 },
	{ SNDRV_PCM_FORMAT_U24_3LE, VIRTIO_SND_PCM_FMT_U24_3 },
	{ SNDRV_PCM_FORMAT_S20_LE, VIRTIO_SND_PCM_FMT_S20 },
	{ SNDRV_PCM_FORMAT_U20_LE, VIRTIO_SND_PCM_FMT_U20 },
	{ SNDRV_PCM_FORMAT_S24_LE, VIRTIO_SND_PCM_FMT_S24 },
	{ SNDRV_PCM_FORMAT_U24_LE, VIRTIO_SND_PCM_FMT_U24 },
	{ SNDRV_PCM_FORMAT_S32_LE, VIRTIO_SND_PCM_FMT_S32 },
	{ SNDRV_PCM_FORMAT_U32_LE, VIRTIO_SND_PCM_FMT_U32 },
	{ SNDRV_PCM_FORMAT_FLOAT_LE, VIRTIO_SND_PCM_FMT_FLOAT },
	{ SNDRV_PCM_FORMAT_FLOAT64_LE, VIRTIO_SND_PCM_FMT_FLOAT64 },
	{ SNDRV_PCM_FORMAT_DSD_U8, VIRTIO_SND_PCM_FMT_DSD_U8 },
	{ SNDRV_PCM_FORMAT_DSD_U16_LE, VIRTIO_SND_PCM_FMT_DSD_U16 },
	{ SNDRV_PCM_FORMAT_DSD_U32_LE, VIRTIO_SND_PCM_FMT_DSD_U32 },
	{ SNDRV_PCM_FORMAT_IEC958_SUBFRAME_LE,
	  VIRTIO_SND_PCM_FMT_IEC958_SUBFRAME }
};

struct virtsnd_a2v_rate {
	unsigned int rate;
	unsigned int vio_bit;
};

static const struct virtsnd_a2v_rate g_a2v_rate_map[] = {
	{ 5512, VIRTIO_SND_PCM_RATE_5512 },
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

static inline struct virtio_pcm_msg *
virtsnd_pcm_msg_alloc(struct virtio_pcm_substream *substream, gfp_t gfp)
{
	struct virtio_device *vdev = substream->snd->vdev;
	struct virtio_pcm_msg *msg;

	msg = devm_kzalloc(&vdev->dev, sizeof(*msg), gfp);
	if (msg) {
		INIT_LIST_HEAD(&msg->list);
		msg->substream = substream;

		sg_init_table(msg->sgs, PCM_MSG_SG_MAX);
		sg_init_one(&msg->sgs[PCM_MSG_SG_XFER], &msg->xfer,
			    sizeof(msg->xfer));
		sg_init_one(&msg->sgs[PCM_MSG_SG_STATUS], &msg->status,
			    sizeof(msg->status));
	}

	return msg;
}

static inline void virtsnd_pcm_msg_free(struct virtio_pcm_msg *msg)
{
	struct virtio_device *vdev = msg->substream->snd->vdev;

	if (msg->one_shot_data)
		devm_kfree(&vdev->dev, msg->one_shot_data);

	devm_kfree(&vdev->dev, msg);
}

void virtsnd_pcm_msg_discard(struct virtio_pcm_substream *substream)
{
	struct virtio_snd *snd = substream->snd;
	struct virtio_snd_queue *queue;
	unsigned long flags;

	if (substream->direction == SNDRV_PCM_STREAM_PLAYBACK)
		queue = virtsnd_tx_queue(snd);
	else
		queue = virtsnd_rx_queue(snd);

	spin_lock_irqsave(&queue->lock, flags);
	while (!list_empty(&substream->msg_list)) {
		struct virtio_pcm_msg *msg =
			list_first_entry(&substream->msg_list,
					 struct virtio_pcm_msg, list);

		list_del(&msg->list);
		virtsnd_pcm_msg_free(msg);
	}
	spin_unlock_irqrestore(&queue->lock, flags);
}

static int __virtsnd_pcm_msg_send(struct virtio_pcm_substream *substream,
				  struct virtio_pcm_msg *msg)
{
	int ret;
	struct virtio_snd *snd = substream->snd;
	struct virtio_device *vdev = snd->vdev;
	struct virtqueue *vqueue;
	struct scatterlist *psgs[PCM_MSG_SG_MAX];
	unsigned int i;
	bool notify = false;

	msg->xfer.stream_id = cpu_to_virtio32(vdev, substream->sid);
	memset(&msg->status, 0, sizeof(msg->status));

	for (i = 0; i < PCM_MSG_SG_MAX; ++i)
		psgs[i] = &msg->sgs[i];

	list_add_tail(&msg->list, &substream->msg_list);

	if (substream->direction == SNDRV_PCM_STREAM_PLAYBACK) {
		vqueue = virtsnd_tx_queue(snd)->vqueue;
		ret = virtqueue_add_sgs(vqueue, psgs, 2, 1, msg, GFP_ATOMIC);
	} else {
		vqueue = virtsnd_rx_queue(snd)->vqueue;
		ret = virtqueue_add_sgs(vqueue, psgs, 1, 2, msg, GFP_ATOMIC);
	}

	if (ret)
		goto on_failure;

	if (!VIRTIO_PCM_HAS_FEATURE(substream->features, MSG_POLLING))
		notify = virtqueue_kick_prepare(vqueue);

	if (notify)
		if (!virtqueue_notify(vqueue))
			goto on_failure;

	return 0;

on_failure:
	list_del(&msg->list);

	return -EIO;
}

static int virtsnd_pcm_msg_send(struct virtio_pcm_substream *substream,
				void *data, size_t size, gfp_t gfp)
{
	int ret;
	struct virtio_snd *snd = substream->snd;
	struct virtio_snd_queue *queue;
	struct virtio_pcm_msg *msg;
	unsigned long flags;

	msg = virtsnd_pcm_msg_alloc(substream, gfp);
	if (!msg)
		return -ENOMEM;

	sg_init_one(&msg->sgs[PCM_MSG_SG_DATA], data, size);

	if (substream->direction == SNDRV_PCM_STREAM_PLAYBACK)
		queue = virtsnd_tx_queue(snd);
	else
		queue = virtsnd_rx_queue(snd);

	spin_lock_irqsave(&queue->lock, flags);
	ret = __virtsnd_pcm_msg_send(substream, msg);
	spin_unlock_irqrestore(&queue->lock, flags);

	if (ret)
		virtsnd_pcm_msg_free(msg);

	return ret;
}

static int virtsnd_pcm_msg_silence_send(struct virtio_pcm_substream *substream,
					gfp_t gfp)
{
	int ret;
	struct virtio_snd *snd = substream->snd;
	struct virtio_device *vdev = snd->vdev;
	struct virtio_snd_queue *queue;
	struct virtio_pcm_msg *msg;
	struct snd_pcm_runtime *runtime = substream->substream->runtime;
	ssize_t size = frames_to_bytes(runtime, runtime->period_size);
	unsigned long flags;

	msg = virtsnd_pcm_msg_alloc(substream, gfp);
	if (!msg)
		return -ENOMEM;

	msg->one_shot_data = devm_kmalloc(&vdev->dev, size, gfp);
	if (!msg->one_shot_data) {
		ret = -ENOMEM;
		goto on_failure;
	}

	ret = snd_pcm_format_set_silence(runtime->format, msg->one_shot_data,
					 bytes_to_samples(runtime, size));
	if (ret)
		goto on_failure;

	sg_init_one(&msg->sgs[PCM_MSG_SG_DATA], msg->one_shot_data, size);

	if (substream->direction == SNDRV_PCM_STREAM_PLAYBACK)
		queue = virtsnd_tx_queue(snd);
	else
		queue = virtsnd_rx_queue(snd);

	spin_lock_irqsave(&queue->lock, flags);
	ret = __virtsnd_pcm_msg_send(substream, msg);
	spin_unlock_irqrestore(&queue->lock, flags);

	if (ret)
		goto on_failure;

	return 0;

on_failure:
	virtsnd_pcm_msg_free(msg);

	return ret;
}

static bool virtsnd_pcm_msg_complete(struct virtio_pcm_msg *msg, size_t size)
{
	struct virtio_pcm_substream *substream = msg->substream;
	struct snd_pcm_runtime *runtime = substream->substream->runtime;
	snd_pcm_uframes_t hw_ptr;

	/* TODO: propagate an error to upper layer? */
	if (le32_to_cpu(msg->status.status) != VIRTIO_SND_S_OK)
		goto on_resend;

	hw_ptr = (snd_pcm_uframes_t)atomic64_read(&substream->hw_ptr);

	if (substream->direction == SNDRV_PCM_STREAM_PLAYBACK) {
		atomic_set(&substream->xfer_xrun, 0);

		hw_ptr += runtime->period_size;
	} else {
		if (size > sizeof(struct virtio_snd_pcm_status))
			size -= sizeof(struct virtio_snd_pcm_status);
		else
			/* TODO: propagate an error to upper layer? */
			goto on_resend;

		hw_ptr += bytes_to_frames(runtime, size);
	}

	if (hw_ptr >= runtime->boundary)
		hw_ptr -= runtime->boundary;

	atomic64_set(&substream->hw_ptr, hw_ptr);

	runtime->delay =
		bytes_to_frames(runtime,
				le32_to_cpu(msg->status.latency_bytes));

	snd_pcm_period_elapsed(substream->substream);

on_resend:
	if (!msg->one_shot_data && !atomic_read(&substream->xfer_draining))
		if (!__virtsnd_pcm_msg_send(substream, msg)) {
			if (substream->direction == SNDRV_PCM_STREAM_CAPTURE)
				atomic_set(&substream->xfer_xrun, 0);
			return true;
		}

	return false;
}

static inline void virtsnd_pcm_notify_cb(struct virtio_device *vdev,
					 struct virtio_snd_queue *queue)
{
	unsigned long flags;

	spin_lock_irqsave(&queue->lock, flags);
	do {
		virtqueue_disable_cb(queue->vqueue);

		for (;;) {
			struct virtio_pcm_substream *substream;
			struct virtio_pcm_msg *msg;
			u32 length;
			bool resent = false;

			msg = virtqueue_get_buf(queue->vqueue, &length);
			if (!msg)
				break;

			list_del(&msg->list);

			substream = msg->substream;

			if (atomic_read(&substream->xfer_enabled))
				resent = virtsnd_pcm_msg_complete(msg, length);

			if (list_empty(&substream->msg_list))
				wake_up_all(&substream->msg_empty);

			if (!resent)
				virtsnd_pcm_msg_free(msg);
		}

		if (unlikely(virtqueue_is_broken(queue->vqueue)))
			break;
	} while (!virtqueue_enable_cb(queue->vqueue));
	spin_unlock_irqrestore(&queue->lock, flags);
}

void virtsnd_pcm_tx_notify_cb(struct virtqueue *vqueue)
{
	struct virtio_snd *snd = vqueue->vdev->priv;

	virtsnd_pcm_notify_cb(snd->vdev, virtsnd_tx_queue(snd));
}

void virtsnd_pcm_rx_notify_cb(struct virtqueue *vqueue)
{
	struct virtio_snd *snd = vqueue->vdev->priv;

	virtsnd_pcm_notify_cb(snd->vdev, virtsnd_rx_queue(snd));
}

struct virtio_snd_msg *
virtsnd_pcm_ctl_msg_alloc(struct virtio_pcm_substream *substream,
			  unsigned int command, gfp_t gfp)
{
	struct virtio_device *vdev = substream->snd->vdev;
	size_t request_size = sizeof(struct virtio_snd_pcm_hdr);
	size_t response_size = sizeof(struct virtio_snd_hdr);
	struct virtio_snd_msg *msg;

	switch (command) {
	case VIRTIO_SND_R_PCM_SET_PARAMS: {
		request_size = sizeof(struct virtio_snd_pcm_set_params);
		break;
	}
	}

	msg = virtsnd_ctl_msg_alloc(vdev, request_size, response_size, gfp);
	if (!IS_ERR(msg)) {
		struct virtio_snd_pcm_hdr *hdr = sg_virt(&msg->sg_request);

		hdr->hdr.code = cpu_to_virtio32(vdev, command);
		hdr->stream_id = cpu_to_virtio32(vdev, substream->sid);
	}

	return msg;
}

int virtsnd_pcm_ctl_set_params(struct virtio_pcm_substream *substream,
			       unsigned int buffer_bytes,
			       unsigned int period_bytes, unsigned int channels,
			       unsigned int format, unsigned int rate)
{
	struct virtio_snd *snd = substream->snd;
	struct virtio_device *vdev = snd->vdev;
	struct virtio_snd_msg *msg;
	struct virtio_snd_pcm_set_params *request;
	int i;
	int vformat = -1;
	int vrate = -1;

	for (i = 0; i < ARRAY_SIZE(g_a2v_format_map); ++i)
		if (g_a2v_format_map[i].alsa_bit == format) {
			vformat = g_a2v_format_map[i].vio_bit;

			break;
		}

	for (i = 0; i < ARRAY_SIZE(g_a2v_rate_map); ++i)
		if (g_a2v_rate_map[i].rate == rate) {
			vrate = g_a2v_rate_map[i].vio_bit;

			break;
		}

	if (vformat == -1 || vrate == -1 || buffer_bytes % period_bytes)
		return -EINVAL;

	msg = virtsnd_pcm_ctl_msg_alloc(substream, VIRTIO_SND_R_PCM_SET_PARAMS,
					GFP_KERNEL);
	if (IS_ERR(msg))
		return PTR_ERR(msg);

	request = sg_virt(&msg->sg_request);

	request->buffer_bytes = cpu_to_virtio32(vdev, buffer_bytes);
	request->period_bytes = cpu_to_virtio32(vdev, period_bytes);

	if (VIRTIO_PCM_HAS_FEATURE(substream->features, MSG_POLLING))
		VIRTIO_PCM_SET_FEATURE(request->features, MSG_POLLING);

	if (VIRTIO_PCM_HAS_FEATURE(substream->features, EVT_XRUNS))
		VIRTIO_PCM_SET_FEATURE(request->features, EVT_XRUNS);

	request->channels = channels;
	request->format = vformat;
	request->rate = vrate;

	return virtsnd_ctl_msg_send_sync(snd, msg);
}

int virtsnd_pcm_ctl_prepare(struct virtio_pcm_substream *substream, bool resume)
{
	int ret;
	struct virtio_snd *snd = substream->snd;
	struct virtio_snd_msg *msg;
	struct snd_pcm_runtime *runtime = substream->substream->runtime;
	ssize_t period_bytes = frames_to_bytes(runtime, runtime->period_size);
	unsigned int i;

	msg = virtsnd_pcm_ctl_msg_alloc(substream, VIRTIO_SND_R_PCM_PREPARE,
					GFP_KERNEL);
	if (IS_ERR(msg))
		return PTR_ERR(msg);

	ret = virtsnd_ctl_msg_send_sync(snd, msg);
	if (ret)
		return ret;

	/*
	 * Pre-buffing with silence on playback resume:
	 */
	if (resume && substream->direction == SNDRV_PCM_STREAM_PLAYBACK)
		for (i = 0; i < runtime->periods; ++i) {
			ret = virtsnd_pcm_msg_silence_send(substream,
							   GFP_KERNEL);
			if (ret)
				return ret;
		}

	/*
	 * The ops->prepare() callback can be called several times in a row.
	 */
	if (list_empty(&substream->msg_list)) {
		u8 *data = runtime->dma_area;

		for (i = 0; i < runtime->periods; ++i, data += period_bytes) {
			ret = virtsnd_pcm_msg_send(substream, data,
						   period_bytes, GFP_KERNEL);
			if (ret)
				return ret;
		}
	}

	return 0;
}
