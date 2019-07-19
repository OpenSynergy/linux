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
#include "virtio_card.h"

static void virtsnd_event_dispatch(struct virtio_snd *snd,
				   struct virtio_snd_event *event)
{
	switch (le32_to_cpu(event->hdr.code)) {
	case VIRTIO_SND_EVT_JACK_CONNECTED:
	case VIRTIO_SND_EVT_JACK_DISCONNECTED: {
		virtsnd_jack_event(snd, event);
		break;
	}
	case VIRTIO_SND_EVT_PCM_PERIOD_ELAPSED:
	case VIRTIO_SND_EVT_PCM_XRUN: {
		virtsnd_pcm_event(snd, event);
		break;
	}
	default: {
		break;
	}
	}
}

static int virtsnd_event_send(struct virtqueue *vqueue,
			      struct virtio_snd_event *event, bool notify,
			      gfp_t gfp)
{
	int ret;
	struct scatterlist sg;
	struct scatterlist *psgs[1] = { &sg };

	/* reset event content */
	memset(event, 0, sizeof(*event));

	sg_init_one(&sg, event, sizeof(*event));

	ret = virtqueue_add_sgs(vqueue, psgs, 0, 1, event, gfp);
	if (ret)
		return ret;

	if (notify)
		if (virtqueue_kick_prepare(vqueue))
			if (!virtqueue_notify(vqueue))
				return -EIO;

	return 0;
}

int virtsnd_event_populate(struct virtqueue *vqueue)
{
	struct virtio_device *vdev = vqueue->vdev;
	struct virtio_snd_event *events;
	unsigned int nevents;
	unsigned int i;

	nevents = virtqueue_get_vring_size(vqueue);

	events = devm_kcalloc(&vdev->dev, nevents, sizeof(*events), GFP_KERNEL);
	if (!events)
		return -ENOMEM;

	for (i = 0; i < nevents; ++i) {
		int ret;

		ret = virtsnd_event_send(vqueue, &events[i], i == nevents - 1,
					 GFP_KERNEL);
		if (ret)
			return ret;
	}

	return 0;
}

void virtsnd_event_notify_cb(struct virtqueue *vqueue)
{
	struct virtio_snd *snd = vqueue->vdev->priv;

	do {
		virtqueue_disable_cb(vqueue);

		for (;;) {
			struct virtio_snd_event *event;
			u32 length;

			event = virtqueue_get_buf(vqueue, &length);
			if (!event)
				break;

			if (atomic_read(&snd->events_enabled))
				virtsnd_event_dispatch(snd, event);
			virtsnd_event_send(vqueue, event, true, GFP_ATOMIC);
		}

		if (unlikely(virtqueue_is_broken(vqueue)))
			break;
	} while (!virtqueue_enable_cb(vqueue));
}
