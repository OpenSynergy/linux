/* SPDX-License-Identifier: GPL-2.0+ */
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
#ifndef VIRTIO_SND_PCM_H
#define VIRTIO_SND_PCM_H

#include <linux/atomic.h>
#include <linux/virtio_config.h>

#include "virtio_card.h"

#define VIRTIO_PCM_HAS_FEATURE(_field_, _feature_) \
	((_field_) & (1U << (VIRTIO_SND_PCM_F_ ## _feature_)))

#define VIRTIO_PCM_SET_FEATURE(_field_, _feature_) \
	((_field_) |= (1U << (VIRTIO_SND_PCM_F_ ## _feature_)))

struct virtio_pcm;

/**
 * struct virtio_pcm_substream - virtio PCM substream representation.
 * @snd: Virtio sound card device.
 * @nid: Function group node identifier.
 * @sid: Stream identifier.
 * @direction: Stream data flow direction (VIRTIO_SND_D_XXX).
 * @features: Stream virtio feature bit map (1 << VIRTIO_SND_PCM_F_XXX).
 * @substream: Kernel substream.
 * @hw: Kernel substream hardware descriptor.
 * @dma_area: Preallocated substream buffer.
 * @hw_ptr: Substream hardware pointer value.
 * @xfer_enabled: Data transfer state.
 * @xfer_draining: Data draining state.
 * @xfer_xrun: Data underflow/overflow state.
 * @msg_list: Pending I/O message list.
 * @msg_empty: msg_list is empty notification.
 */
struct virtio_pcm_substream {
	struct virtio_snd *snd;
	unsigned int nid;
	unsigned int sid;
	u32 direction;
	u32 features;
	struct snd_pcm_substream *substream;
	struct snd_pcm_hardware hw;
	void *dma_area;
	atomic64_t hw_ptr;
	atomic_t xfer_enabled;
	atomic_t xfer_draining;
	atomic_t xfer_xrun;
	struct list_head msg_list;
	wait_queue_head_t msg_empty;
};

/**
 * struct virtio_pcm_stream - virtio PCM stream representation.
 * @substreams: Virtio substreams belonging to the stream.
 * @nsubstreams: Number of substreams.
 * @chmaps: Kernel channel maps belonging to the stream.
 * @nchmaps: Number of channel maps.
 */
struct virtio_pcm_stream {
	struct virtio_pcm_substream **substreams;
	unsigned int nsubstreams;
	struct snd_pcm_chmap_elem *chmaps;
	unsigned int nchmaps;
};

/**
 * struct virtio_pcm - virtio PCM device representation.
 * @list: PCM list entry.
 * @nid: Function group node identifier.
 * @pcm: Kernel PCM device.
 * @streams: Virtio streams (playback and capture).
 * @jacks: Virtio jacks belonging to the PCM device.
 * @njacks: Number of jacks.
 */
struct virtio_pcm {
	struct list_head list;
	unsigned int nid;
	struct snd_pcm *pcm;
	struct virtio_pcm_stream streams[SNDRV_PCM_STREAM_LAST + 1];
	struct virtio_jack **jacks;
	unsigned int njacks;
};

extern const struct snd_pcm_ops virtsnd_pcm_ops;

struct virtio_pcm *virtsnd_pcm_find(struct virtio_snd *snd, unsigned int nid);

struct virtio_pcm *virtsnd_pcm_find_or_create(struct virtio_snd *snd,
					      unsigned int nid);

void virtsnd_pcm_msg_discard(struct virtio_pcm_substream *substream);

struct virtio_snd_msg *
virtsnd_pcm_ctl_msg_alloc(struct virtio_pcm_substream *substream,
			  unsigned int command, gfp_t gfp);

int virtsnd_pcm_ctl_set_params(struct virtio_pcm_substream *substream,
			       unsigned int buffer_bytes,
			       unsigned int period_bytes, unsigned int channels,
			       unsigned int format, unsigned int rate);

int virtsnd_pcm_ctl_prepare(struct virtio_pcm_substream *substream,
			    bool resume);

#endif /* VIRTIO_SND_PCM_H */
