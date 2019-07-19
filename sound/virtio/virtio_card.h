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
#ifndef VIRTIO_SND_CARD_H
#define VIRTIO_SND_CARD_H

#include <linux/virtio.h>
#include <sound/core.h>
#include <sound/pcm.h>
#include <uapi/linux/virtio_snd.h>

#include "virtio_ctl_msg.h"

struct virtio_jack;
struct virtio_pcm_substream;

/**
 * struct virtio_snd_queue - Virtqueue wrapper structure.
 * @lock: Used to synchronize access to a virtqueue.
 * @vqueue: Underlying virtqueue.
 */
struct virtio_snd_queue {
	spinlock_t lock;
	struct virtqueue *vqueue;
};

/**
 * struct virtio_snd - Virtio sound card device representation.
 * @vdev: Underlying virtio device.
 * @queues: Virtqueue wrappers.
 * @events_enabled: Event handling state.
 * @card: Kernel sound card device.
 * @pcm_list: List of virtio PCM devices.
 * @jacks: Virtio jacks.
 * @njacks: Number of jacks.
 * @substreams: Virtio PCM substreams.
 * @nsubstreams: Number of PCM stream.
 */
struct virtio_snd {
	struct virtio_device *vdev;
	struct virtio_snd_queue *queues[VIRTIO_SND_VQ_MAX];
	atomic_t events_enabled;
	struct snd_card *card;
	struct list_head pcm_list;
	struct virtio_jack *jacks;
	unsigned int njacks;
	struct virtio_pcm_substream *substreams;
	unsigned int nsubstreams;
};

static inline struct virtio_snd_queue *
virtsnd_control_queue(struct virtio_snd *snd)
{
	return snd->queues[VIRTIO_SND_VQ_CONTROL];
}

static inline struct virtio_snd_queue *
virtsnd_event_queue(struct virtio_snd *snd)
{
	return snd->queues[VIRTIO_SND_VQ_EVENT];
}

static inline struct virtio_snd_queue *
virtsnd_tx_queue(struct virtio_snd *snd)
{
	return snd->queues[VIRTIO_SND_VQ_TX];
}

static inline struct virtio_snd_queue *
virtsnd_rx_queue(struct virtio_snd *snd)
{
	return snd->queues[VIRTIO_SND_VQ_RX];
}

/*
 * event related public functions:
 */
int virtsnd_event_populate(struct virtqueue *vqueue);

void virtsnd_event_notify_cb(struct virtqueue *vqueue);

/*
 * jack related public functions:
 */
int virtsnd_jack_parse_cfg(struct virtio_snd *snd);

int virtsnd_jack_build_devs(struct virtio_snd *snd);

void virtsnd_jack_event(struct virtio_snd *snd,
			struct virtio_snd_event *event);

/*
 * PCM device related public functions:
 */
int virtsnd_pcm_validate(struct virtio_device *vdev);

int virtsnd_pcm_parse_cfg(struct virtio_snd *snd);

int virtsnd_pcm_build_devs(struct virtio_snd *snd);

#ifdef CONFIG_PM_SLEEP
int virtsnd_pcm_freeze(struct virtio_snd *snd);

int virtsnd_pcm_restore(struct virtio_snd *snd);
#endif /* CONFIG_PM_SLEEP */

void virtsnd_pcm_event(struct virtio_snd *snd, struct virtio_snd_event *event);

void virtsnd_pcm_tx_notify_cb(struct virtqueue *vqueue);

void virtsnd_pcm_rx_notify_cb(struct virtqueue *vqueue);

/*
 * channel map related public functions:
 */
int virtsnd_chmap_parse_cfg(struct virtio_snd *snd);

int virtsnd_chmap_build_devs(struct virtio_snd *snd);

#endif /* VIRTIO_SND_CARD_H */
