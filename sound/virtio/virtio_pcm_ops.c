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

static int virtsnd_pcm_open(struct snd_pcm_substream *substream)
{
	struct virtio_pcm *pcm = snd_pcm_substream_chip(substream);
	struct virtio_pcm_substream *vsubstream = NULL;

	if (pcm) {
		switch (substream->stream) {
		case SNDRV_PCM_STREAM_PLAYBACK:
		case SNDRV_PCM_STREAM_CAPTURE: {
			struct virtio_pcm_stream *vstream =
				&pcm->streams[substream->stream];

			if (substream->number < vstream->nsubstreams)
				vsubstream =
					vstream->substreams[substream->number];
			break;
		}
		}
	}

	if (!vsubstream)
		return -EBADFD;

	substream->runtime->hw = vsubstream->hw;
	substream->private_data = vsubstream;

	return 0;
}

static int virtsnd_pcm_close(struct snd_pcm_substream *substream)
{
	return 0;
}

static int virtsnd_pcm_hw_params(struct snd_pcm_substream *substream,
				 struct snd_pcm_hw_params *hw_params)
{
	int ret;
	struct virtio_pcm_substream *ss = snd_pcm_substream_chip(substream);
	struct snd_pcm_runtime *runtime = substream->runtime;
	snd_pcm_format_t format;
	unsigned int channels;
	unsigned int rate;
	u32 buffer_bytes;
	u32 period_bytes;

	format = params_format(hw_params);
	channels = snd_pcm_hw_param_value(hw_params,
					  SNDRV_PCM_HW_PARAM_CHANNELS, NULL);
	rate = snd_pcm_hw_param_value(hw_params,
				      SNDRV_PCM_HW_PARAM_RATE, NULL);
	buffer_bytes = snd_pcm_hw_param_value(hw_params,
					      SNDRV_PCM_HW_PARAM_BUFFER_BYTES,
					      NULL);
	period_bytes = params_period_bytes(hw_params);

	ret = virtsnd_pcm_ctl_set_params(ss, buffer_bytes, period_bytes,
					 channels, format, rate);
	if (!ret) {
		runtime->dma_area = ss->dma_area;
		runtime->dma_bytes = buffer_bytes;
	}

	return ret;
}

static int virtsnd_pcm_hw_free(struct snd_pcm_substream *substream)
{
	int ret;
	struct virtio_pcm_substream *ss = snd_pcm_substream_chip(substream);
	struct virtio_snd *snd = ss->snd;
	struct virtio_snd_msg *msg;
	struct virtio_snd_queue *queue;
	struct snd_pcm_runtime *runtime = substream->runtime;

	runtime->dma_area = NULL;
	runtime->dma_bytes = 0;

	msg = virtsnd_pcm_ctl_msg_alloc(ss, VIRTIO_SND_R_PCM_RELEASE,
					GFP_KERNEL);
	if (IS_ERR(msg))
		return PTR_ERR(msg);

	ret = virtsnd_ctl_msg_send_sync(snd, msg);
	if (ret)
		return ret;

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
		queue = virtsnd_tx_queue(snd);
	else
		queue = virtsnd_rx_queue(snd);

	return wait_event_interruptible_lock_irq(ss->msg_empty,
						 list_empty(&ss->msg_list),
						 queue->lock);
}

static int virtsnd_pcm_prepare(struct snd_pcm_substream *substream)
{
	struct virtio_pcm_substream *ss = snd_pcm_substream_chip(substream);

	atomic64_set(&ss->hw_ptr, 0);
	atomic_set(&ss->xfer_enabled, 0);
	atomic_set(&ss->xfer_draining, 0);
	atomic_set(&ss->xfer_xrun, 0);

	return virtsnd_pcm_ctl_prepare(ss, false);
}

static int virtsnd_pcm_trigger(struct snd_pcm_substream *substream, int command)
{
	struct virtio_pcm_substream *ss = snd_pcm_substream_chip(substream);
	struct virtio_snd *snd = ss->snd;
	struct virtio_snd_msg *msg;

	switch (command) {
	case SNDRV_PCM_TRIGGER_START:
	case SNDRV_PCM_TRIGGER_RESUME: {
		atomic_set(&ss->xfer_enabled, 1);

		msg = virtsnd_pcm_ctl_msg_alloc(ss, VIRTIO_SND_R_PCM_START,
						GFP_ATOMIC);
		if (IS_ERR(msg))
			return PTR_ERR(msg);

		return virtsnd_ctl_msg_send(snd, msg);
	}
	case SNDRV_PCM_TRIGGER_STOP:
	case SNDRV_PCM_TRIGGER_SUSPEND: {
		atomic_set(&ss->xfer_enabled, 0);

		msg = virtsnd_pcm_ctl_msg_alloc(ss, VIRTIO_SND_R_PCM_STOP,
						GFP_ATOMIC);
		if (IS_ERR(msg))
			return PTR_ERR(msg);

		return virtsnd_ctl_msg_send(snd, msg);
	}
	case SNDRV_PCM_TRIGGER_DRAIN: {
		atomic_set(&ss->xfer_draining, 1);

		return 0;
	}
	default: {
		return -EINVAL;
	}
	}
}

static snd_pcm_uframes_t
virtsnd_pcm_pointer(struct snd_pcm_substream *substream)
{
	struct virtio_pcm_substream *ss = snd_pcm_substream_chip(substream);
	snd_pcm_uframes_t hw_ptr;

	if (atomic_read(&ss->xfer_xrun))
		return SNDRV_PCM_POS_XRUN;

	hw_ptr = (snd_pcm_uframes_t)atomic64_read(&ss->hw_ptr);

	return hw_ptr % substream->runtime->buffer_size;
}

static int virtsnd_pcm_mmap(struct snd_pcm_substream *substream,
			    struct vm_area_struct *vma)
{
	struct snd_pcm_runtime *runtime = substream->runtime;

	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;

	return remap_pfn_range(vma, vma->vm_start,
			       virt_to_phys(runtime->dma_area) >> PAGE_SHIFT,
			       vma->vm_end - vma->vm_start, vma->vm_page_prot);
}

const struct snd_pcm_ops virtsnd_pcm_ops = {
	.open = virtsnd_pcm_open,
	.close = virtsnd_pcm_close,
	.ioctl = snd_pcm_lib_ioctl,
	.hw_params = virtsnd_pcm_hw_params,
	.hw_free = virtsnd_pcm_hw_free,
	.prepare = virtsnd_pcm_prepare,
	.trigger = virtsnd_pcm_trigger,
	.pointer = virtsnd_pcm_pointer,
	.mmap = virtsnd_pcm_mmap
};
