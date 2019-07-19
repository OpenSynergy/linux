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
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/virtio_config.h>
#include <sound/initval.h>
#include <uapi/linux/virtio_ids.h>

#include "virtio_card.h"

static int virtsnd_find_vqs(struct virtio_snd *snd)
{
	int ret;
	int i;
	struct virtio_device *vdev = snd->vdev;
	vq_callback_t *callbacks[VIRTIO_SND_VQ_MAX] = {
		virtsnd_ctl_notify_cb,
		virtsnd_event_notify_cb,
		virtsnd_pcm_tx_notify_cb,
		virtsnd_pcm_rx_notify_cb
	};
	const char *names[VIRTIO_SND_VQ_MAX] = {
		"virtsnd-ctl", "virtsnd-event", "virtsnd-tx", "virtsnd-rx"
	};
	struct virtqueue *vqs[VIRTIO_SND_VQ_MAX] = { 0 };

	ret = virtio_find_vqs(vdev, VIRTIO_SND_VQ_MAX, vqs, callbacks, names,
			      NULL);
	if (ret) {
		dev_err(&vdev->dev, "Failed to initialize virtqueues");
		return ret;
	}

	for (i = 0; i < VIRTIO_SND_VQ_MAX; ++i)
		snd->queues[i]->vqueue = vqs[i];

	ret = virtsnd_event_populate(vqs[VIRTIO_SND_VQ_EVENT]);
	if (ret)
		return ret;

	return 0;
}

static int virtsnd_validate(struct virtio_device *vdev)
{
	if (!vdev->config->get) {
		dev_err(&vdev->dev, "Config access disabled");
		return -EINVAL;
	}

	if (virtsnd_pcm_validate(vdev))
		return -EINVAL;

	return 0;
}

static void virtsnd_remove(struct virtio_device *vdev)
{
	struct virtio_snd *snd = vdev->priv;

	if (!snd)
		return;

	if (snd->card)
		snd_card_free(snd->card);

	vdev->config->reset(vdev);
	vdev->config->del_vqs(vdev);

	vdev->priv = NULL;
}

static int virtsnd_probe(struct virtio_device *vdev)
{
	static int g_ndevices;
	static int g_indexes[SNDRV_CARDS] = SNDRV_DEFAULT_IDX;
	static char *g_ids[SNDRV_CARDS] = SNDRV_DEFAULT_STR;
	static struct snd_device_ops ops = { 0 };

	int ret;
	unsigned int i;
	struct virtio_snd *snd;

	if (g_ndevices >= SNDRV_CARDS)
		return -ENODEV;

	snd = devm_kzalloc(&vdev->dev, sizeof(*snd), GFP_KERNEL);
	if (!snd)
		return -ENOMEM;

	snd->vdev = vdev;
	INIT_LIST_HEAD(&snd->pcm_list);

	vdev->priv = snd;

	for (i = 0; i < VIRTIO_SND_VQ_MAX; ++i) {
		snd->queues[i] = devm_kzalloc(&vdev->dev,
					      sizeof(*snd->queues[i]),
					      GFP_KERNEL);
		if (!snd->queues[i])
			return -ENOMEM;

		spin_lock_init(&snd->queues[i]->lock);
	}

	ret = virtsnd_find_vqs(snd);
	if (ret)
		return ret;

	virtio_device_ready(vdev);

	ret = snd_card_new(&vdev->dev, g_indexes[g_ndevices],
			   g_ids[g_ndevices], THIS_MODULE, 0, &snd->card);
	if (ret < 0)
		goto on_failure;

	strlcpy(snd->card->id, "viosnd", sizeof(snd->card->id));
	strlcpy(snd->card->driver, "virtio_snd", sizeof(snd->card->driver));
	strlcpy(snd->card->shortname, "VIOSND", sizeof(snd->card->shortname));
	strlcpy(snd->card->longname, "VirtIO Sound Card",
		sizeof(snd->card->longname));
	snd->card->private_data = snd;

	ret = snd_device_new(snd->card, SNDRV_DEV_LOWLEVEL, snd, &ops);
	if (ret < 0)
		goto on_failure;

	ret = virtsnd_jack_parse_cfg(snd);
	if (ret)
		goto on_failure;

	ret = virtsnd_pcm_parse_cfg(snd);
	if (ret)
		goto on_failure;

	ret = virtsnd_chmap_parse_cfg(snd);
	if (ret)
		goto on_failure;

	if (snd->njacks) {
		ret = virtsnd_jack_build_devs(snd);
		if (ret)
			goto on_failure;
	}

	if (snd->nsubstreams) {
		ret = virtsnd_pcm_build_devs(snd);
		if (ret)
			goto on_failure;
	}

	ret = virtsnd_chmap_build_devs(snd);
	if (ret)
		goto on_failure;

	ret = snd_card_register(snd->card);
	if (!ret)
		g_ndevices++;

	atomic_set(&snd->events_enabled, 1);

on_failure:
	if (ret)
		virtsnd_remove(vdev);

	return ret;
}

#ifdef CONFIG_PM_SLEEP
static int virtsnd_freeze(struct virtio_device *vdev)
{
	int ret;
	struct virtio_snd *snd = vdev->priv;

	if (snd->nsubstreams) {
		ret = virtsnd_pcm_freeze(snd);
		if (ret)
			return ret;
	}

	vdev->config->reset(vdev);
	vdev->config->del_vqs(vdev);

	return 0;
}

static int virtsnd_restore(struct virtio_device *vdev)
{
	int ret;
	struct virtio_snd *snd = vdev->priv;

	ret = virtsnd_find_vqs(snd);
	if (ret)
		return ret;

	virtio_device_ready(vdev);

	if (snd->nsubstreams) {
		ret = virtsnd_pcm_restore(snd);
		if (ret)
			return ret;
	}

	return 0;
}
#endif /* CONFIG_PM_SLEEP */

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_SOUND, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver virtsnd_driver = {
	.driver.name = KBUILD_MODNAME,
	.driver.owner = THIS_MODULE,
	.id_table = id_table,
	.validate = virtsnd_validate,
	.probe = virtsnd_probe,
	.remove = virtsnd_remove,
#ifdef CONFIG_PM_SLEEP
	.freeze = virtsnd_freeze,
	.restore = virtsnd_restore,
#endif
};

static int __init init(void)
{
	return register_virtio_driver(&virtsnd_driver);
}
module_init(init);

static void __exit fini(void)
{
	unregister_virtio_driver(&virtsnd_driver);
}
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio sound card driver");
MODULE_LICENSE("GPL");
