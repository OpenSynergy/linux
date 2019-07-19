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
#include <linux/moduleparam.h>
#include <linux/virtio_config.h>

#include "virtio_pcm.h"

/**
 * DOC: PCM-related Module Parameters
 *
 * ``pcm_buffer_ms``
 *
 * Hardware buffer size (expressed in milliseconds) for both the playback and
 * capture substreams.
 *
 * ``pcm_periods_min``
 *
 * The minimum number of periods in the hardware buffer.
 *
 * ``pcm_periods_max``
 *
 * The maximum number of periods in the hardware buffer.
 */
static int pcm_buffer_ms = 250;
module_param(pcm_buffer_ms, int, 0644);
MODULE_PARM_DESC(pcm_buffer_ms, "PCM substream buffer size in milliseconds");

static int pcm_periods_min = 4;
module_param(pcm_periods_min, int, 0644);
MODULE_PARM_DESC(pcm_periods_min, "Minimum number of periods");

static int pcm_periods_max = 8;
module_param(pcm_periods_max, int, 0644);
MODULE_PARM_DESC(pcm_periods_max, "Maximum number of periods");

static const unsigned int g_v2a_format_map[] = {
	[VIRTIO_SND_PCM_FMT_IMA_ADPCM] = SNDRV_PCM_FORMAT_IMA_ADPCM,
	[VIRTIO_SND_PCM_FMT_MU_LAW] = SNDRV_PCM_FORMAT_MU_LAW,
	[VIRTIO_SND_PCM_FMT_A_LAW] = SNDRV_PCM_FORMAT_A_LAW,
	[VIRTIO_SND_PCM_FMT_S8] = SNDRV_PCM_FORMAT_S8,
	[VIRTIO_SND_PCM_FMT_U8] = SNDRV_PCM_FORMAT_U8,
	[VIRTIO_SND_PCM_FMT_S16] = SNDRV_PCM_FORMAT_S16_LE,
	[VIRTIO_SND_PCM_FMT_U16] = SNDRV_PCM_FORMAT_U16_LE,
	[VIRTIO_SND_PCM_FMT_S18_3] = SNDRV_PCM_FORMAT_S18_3LE,
	[VIRTIO_SND_PCM_FMT_U18_3] = SNDRV_PCM_FORMAT_U18_3LE,
	[VIRTIO_SND_PCM_FMT_S20_3] = SNDRV_PCM_FORMAT_S20_3LE,
	[VIRTIO_SND_PCM_FMT_U20_3] = SNDRV_PCM_FORMAT_U20_3LE,
	[VIRTIO_SND_PCM_FMT_S24_3] = SNDRV_PCM_FORMAT_S24_3LE,
	[VIRTIO_SND_PCM_FMT_U24_3] = SNDRV_PCM_FORMAT_U24_3LE,
	[VIRTIO_SND_PCM_FMT_S20] = SNDRV_PCM_FORMAT_S20_LE,
	[VIRTIO_SND_PCM_FMT_U20] = SNDRV_PCM_FORMAT_U20_LE,
	[VIRTIO_SND_PCM_FMT_S24] = SNDRV_PCM_FORMAT_S24_LE,
	[VIRTIO_SND_PCM_FMT_U24] = SNDRV_PCM_FORMAT_U24_LE,
	[VIRTIO_SND_PCM_FMT_S32] = SNDRV_PCM_FORMAT_S32_LE,
	[VIRTIO_SND_PCM_FMT_U32] = SNDRV_PCM_FORMAT_U32_LE,
	[VIRTIO_SND_PCM_FMT_FLOAT] = SNDRV_PCM_FORMAT_FLOAT_LE,
	[VIRTIO_SND_PCM_FMT_FLOAT64] = SNDRV_PCM_FORMAT_FLOAT64_LE,
	[VIRTIO_SND_PCM_FMT_DSD_U8] = SNDRV_PCM_FORMAT_DSD_U8,
	[VIRTIO_SND_PCM_FMT_DSD_U16] = SNDRV_PCM_FORMAT_DSD_U16_LE,
	[VIRTIO_SND_PCM_FMT_DSD_U32] = SNDRV_PCM_FORMAT_DSD_U32_LE,
	[VIRTIO_SND_PCM_FMT_IEC958_SUBFRAME] =
		SNDRV_PCM_FORMAT_IEC958_SUBFRAME_LE
};

struct virtsnd_v2a_rate {
	unsigned int alsa_bit;
	unsigned int rate;
};

static const struct virtsnd_v2a_rate g_v2a_rate_map[] = {
	[VIRTIO_SND_PCM_RATE_5512] = { SNDRV_PCM_RATE_5512, 5512 },
	[VIRTIO_SND_PCM_RATE_8000] = { SNDRV_PCM_RATE_8000, 8000 },
	[VIRTIO_SND_PCM_RATE_11025] = { SNDRV_PCM_RATE_11025, 11025 },
	[VIRTIO_SND_PCM_RATE_16000] = { SNDRV_PCM_RATE_16000, 16000 },
	[VIRTIO_SND_PCM_RATE_22050] = { SNDRV_PCM_RATE_22050, 22050 },
	[VIRTIO_SND_PCM_RATE_32000] = { SNDRV_PCM_RATE_32000, 32000 },
	[VIRTIO_SND_PCM_RATE_44100] = { SNDRV_PCM_RATE_44100, 44100 },
	[VIRTIO_SND_PCM_RATE_48000] = { SNDRV_PCM_RATE_48000, 48000 },
	[VIRTIO_SND_PCM_RATE_64000] = { SNDRV_PCM_RATE_64000, 64000 },
	[VIRTIO_SND_PCM_RATE_88200] = { SNDRV_PCM_RATE_88200, 88200 },
	[VIRTIO_SND_PCM_RATE_96000] = { SNDRV_PCM_RATE_96000, 96000 },
	[VIRTIO_SND_PCM_RATE_176400] = { SNDRV_PCM_RATE_176400, 176400 },
	[VIRTIO_SND_PCM_RATE_192000] = { SNDRV_PCM_RATE_192000, 192000 }
};

static int virtsnd_pcm_parse_stream_cfg(struct virtio_snd *snd,
					unsigned int sid,
					struct virtio_snd_pcm_info *info)
{
	struct virtio_device *vdev = snd->vdev;
	struct virtio_pcm *pcm;
	struct virtio_pcm_substream *substream = &snd->substreams[sid];
	unsigned int i;
	u32 sample_size_max = 0;
	u64 values;
	size_t size;
	int order;

	substream->nid = le32_to_cpu(info->hdr.hda_fn_nid);

	pcm = virtsnd_pcm_find_or_create(snd, substream->nid);
	if (IS_ERR(pcm))
		return PTR_ERR(pcm);

	substream->snd = snd;
	substream->sid = sid;
	INIT_LIST_HEAD(&substream->msg_list);
	init_waitqueue_head(&substream->msg_empty);

	switch (info->direction) {
	case VIRTIO_SND_D_OUTPUT: {
		substream->direction = SNDRV_PCM_STREAM_PLAYBACK;
		break;
	}
	case VIRTIO_SND_D_INPUT: {
		substream->direction = SNDRV_PCM_STREAM_CAPTURE;
		break;
	}
	default: {
		dev_err(&vdev->dev,
			"substream #%u: unknown dataflow direction (%u)", sid,
			info->direction);
		return -EINVAL;
	}
	}

	pcm->streams[substream->direction].nsubstreams++;

	substream->features = le32_to_cpu(info->features);

	/*
	 * TODO: set SNDRV_PCM_INFO_{BATCH,BLOCK_TRANSFER} if device supports
	 * only message-based transport.
	 */
	substream->hw.info =
		SNDRV_PCM_INFO_MMAP |
		SNDRV_PCM_INFO_MMAP_VALID |
		SNDRV_PCM_INFO_BATCH |
		SNDRV_PCM_INFO_BLOCK_TRANSFER |
		SNDRV_PCM_INFO_INTERLEAVED |
		SNDRV_PCM_INFO_RESUME |
		SNDRV_PCM_INFO_DRAIN_TRIGGER;

	substream->hw.channels_min = info->channels_min;
	substream->hw.channels_max = info->channels_max;

	values = le64_to_cpu(info->formats);

	for (i = 0; i < ARRAY_SIZE(g_v2a_format_map); ++i)
		if (values & (1ULL << i)) {
			unsigned int alsa_fmt = g_v2a_format_map[i];
			int bytes = snd_pcm_format_physical_width(alsa_fmt) / 8;

			if (sample_size_max < bytes)
				sample_size_max = bytes;

			substream->hw.formats |= (1ULL << alsa_fmt);
		}

	if (!substream->hw.formats) {
		dev_err(&vdev->dev,
			"substream #%u: no supported PCM sample formats found",
			sid);
		return -EINVAL;
	}

	values = le64_to_cpu(info->rates);

	for (i = 0; i < ARRAY_SIZE(g_v2a_rate_map); ++i)
		if (values & (1ULL << i)) {
			if (!substream->hw.rate_min ||
			    substream->hw.rate_min > g_v2a_rate_map[i].rate)
				substream->hw.rate_min = g_v2a_rate_map[i].rate;

			if (substream->hw.rate_max < g_v2a_rate_map[i].rate)
				substream->hw.rate_max = g_v2a_rate_map[i].rate;

			substream->hw.rates |= g_v2a_rate_map[i].alsa_bit;
		}

	if (!substream->hw.rates) {
		dev_err(&vdev->dev,
			"substream #%u: no supported PCM frame rates found",
			sid);
		return -EINVAL;
	}

	substream->hw.periods_min = pcm_periods_min;
	substream->hw.periods_max = pcm_periods_max;

	/*
	 * buffer_bytes_max is {pcm_buffer_ms} for maximum possible combination
	 * of (format, channels, rate) tuples rounded to a page boundary.
	 */
	size = sample_size_max * substream->hw.channels_max * pcm_buffer_ms *
	       (substream->hw.rate_max / MSEC_PER_SEC);

	order = get_order(size);

	substream->hw.buffer_bytes_max = (1ULL << order) * PAGE_SIZE;
	substream->hw.period_bytes_min =
		substream->hw.buffer_bytes_max / substream->hw.periods_max;
	substream->hw.period_bytes_max =
		substream->hw.buffer_bytes_max / substream->hw.periods_min;

	substream->dma_area = (void *)devm_get_free_pages(&vdev->dev,
							  GFP_KERNEL, order);
	if (!substream->dma_area)
		return -ENOMEM;

	return 0;
}

struct virtio_pcm *virtsnd_pcm_find(struct virtio_snd *snd, unsigned int nid)
{
	struct virtio_pcm *pcm;

	list_for_each_entry(pcm, &snd->pcm_list, list)
		if (pcm->nid == nid)
			return pcm;

	return ERR_PTR(-ENOENT);
}

struct virtio_pcm *virtsnd_pcm_find_or_create(struct virtio_snd *snd,
					      unsigned int nid)
{
	struct virtio_device *vdev = snd->vdev;
	struct virtio_pcm *pcm;

	pcm = virtsnd_pcm_find(snd, nid);
	if (!IS_ERR(pcm))
		return pcm;

	pcm = devm_kzalloc(&vdev->dev, sizeof(*pcm), GFP_KERNEL);
	if (!pcm)
		return ERR_PTR(-ENOMEM);

	pcm->nid = nid;
	list_add_tail(&pcm->list, &snd->pcm_list);

	return pcm;
}

int virtsnd_pcm_validate(struct virtio_device *vdev)
{
	if (!pcm_buffer_ms) {
		dev_err(&vdev->dev, "pcm_buffer_ms can not be zero\n");
		return -EINVAL;
	}

	if (!pcm_periods_min) {
		dev_err(&vdev->dev, "pcm_periods_min can not be zero\n");
		return -EINVAL;
	}

	if (!pcm_periods_max) {
		dev_err(&vdev->dev, "pcm_periods_max can not be zero\n");
		return -EINVAL;
	}

	if (pcm_periods_min > pcm_periods_max) {
		dev_err(&vdev->dev,
			"pcm_periods_min (%d) > pcm_periods_max (%d)\n",
			pcm_periods_min, pcm_periods_max);
		return -EINVAL;
	}

	dev_info(&vdev->dev, "pcm_buffer_ms=%u pcm_periods=[%u %u]\n",
		 pcm_buffer_ms, pcm_periods_min, pcm_periods_max);

	return 0;
}

int virtsnd_pcm_parse_cfg(struct virtio_snd *snd)
{
	struct virtio_device *vdev = snd->vdev;
	struct virtio_snd_pcm_info *info;
	unsigned int i;
	int ret;

	virtio_cread(vdev, struct virtio_snd_config, streams,
		     &snd->nsubstreams);
	if (!snd->nsubstreams)
		return 0;

	snd->substreams = devm_kcalloc(&vdev->dev, snd->nsubstreams,
				       sizeof(*snd->substreams), GFP_KERNEL);
	if (!snd->substreams)
		return -ENOMEM;

	info = devm_kcalloc(&vdev->dev, snd->nsubstreams, sizeof(*info),
			    GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	ret = virtsnd_ctl_query_info(snd, VIRTIO_SND_R_PCM_INFO, 0,
				     snd->nsubstreams, sizeof(*info), info);
	if (ret)
		return ret;

	for (i = 0; i < snd->nsubstreams; ++i) {
		ret = virtsnd_pcm_parse_stream_cfg(snd, i, &info[i]);
		if (ret)
			return ret;
	}

	devm_kfree(&vdev->dev, info);

	return 0;
}

int virtsnd_pcm_build_devs(struct virtio_snd *snd)
{
	struct virtio_device *vdev = snd->vdev;
	struct virtio_pcm *pcm;
	unsigned int i;
	int ret;

	list_for_each_entry(pcm, &snd->pcm_list, list) {
		unsigned int npbs =
			pcm->streams[SNDRV_PCM_STREAM_PLAYBACK].nsubstreams;
		unsigned int ncps =
			pcm->streams[SNDRV_PCM_STREAM_CAPTURE].nsubstreams;

		if (!npbs && !ncps)
			continue;

		ret = snd_pcm_new(snd->card, "virtio_snd", pcm->nid, npbs,
				  ncps, &pcm->pcm);
		if (ret) {
			dev_err(&vdev->dev, "snd_pcm_new[%u] failed: %d",
				pcm->nid, ret);
			return ret;
		}

		pcm->pcm->info_flags = 0;
		pcm->pcm->dev_class = SNDRV_PCM_CLASS_GENERIC;
		pcm->pcm->dev_subclass = SNDRV_PCM_SUBCLASS_GENERIC_MIX;
		strlcpy(pcm->pcm->name, "VirtIO PCM", sizeof(pcm->pcm->name));
		pcm->pcm->private_data = pcm;

		for (i = 0; i < ARRAY_SIZE(pcm->streams); ++i) {
			struct virtio_pcm_stream *stream = &pcm->streams[i];

			if (!stream->nsubstreams)
				continue;

			stream->substreams =
				devm_kcalloc(&vdev->dev,
					     stream->nsubstreams,
					     sizeof(*stream->substreams),
					     GFP_KERNEL);
			if (!stream->substreams)
				return -ENOMEM;

			stream->nsubstreams = 0;
		}
	}

	for (i = 0; i < snd->nsubstreams; ++i) {
		struct virtio_pcm_substream *substream = &snd->substreams[i];
		struct virtio_pcm_stream *stream;

		pcm = virtsnd_pcm_find(snd, substream->nid);
		if (IS_ERR(pcm))
			return PTR_ERR(pcm);

		stream = &pcm->streams[substream->direction];
		stream->substreams[stream->nsubstreams++] = substream;
	}

	list_for_each_entry(pcm, &snd->pcm_list, list)
		for (i = 0; i < ARRAY_SIZE(pcm->streams); ++i) {
			struct virtio_pcm_stream *stream = &pcm->streams[i];
			struct snd_pcm_str *kstream;
			struct snd_pcm_substream *ksubstream;

			if (!stream->nsubstreams)
				continue;

			kstream = &pcm->pcm->streams[i];
			ksubstream = kstream->substream;

			while (ksubstream) {
				struct virtio_pcm_substream *substream =
					stream->substreams[ksubstream->number];

				substream->substream = ksubstream;
				ksubstream = ksubstream->next;
			}

			snd_pcm_set_ops(pcm->pcm, i, &virtsnd_pcm_ops);
		}

	return 0;
}

#ifdef CONFIG_PM_SLEEP
int virtsnd_pcm_freeze(struct virtio_snd *snd)
{
	unsigned int i;

	for (i = 0; i < snd->nsubstreams; ++i)
		virtsnd_pcm_msg_discard(&snd->substreams[i]);

	return 0;
}

int virtsnd_pcm_restore(struct virtio_snd *snd)
{
	unsigned int i;

	for (i = 0; i < snd->nsubstreams; ++i) {
		struct virtio_pcm_substream *substream = &snd->substreams[i];
		struct snd_pcm_runtime *runtime;
		unsigned int buffer_bytes;
		unsigned int period_bytes;
		int ret;

		runtime = substream->substream->runtime;
		if (!runtime || !runtime->status ||
		    runtime->status->state != SNDRV_PCM_STATE_SUSPENDED)
			continue;

		buffer_bytes = frames_to_bytes(runtime, runtime->buffer_size);
		period_bytes = frames_to_bytes(runtime, runtime->period_size);

		ret = virtsnd_pcm_ctl_set_params(substream, buffer_bytes,
						 period_bytes,
						 runtime->channels,
						 runtime->format,
						 runtime->rate);
		if (ret)
			return ret;

		ret = virtsnd_pcm_ctl_prepare(substream, true);
		if (ret)
			return ret;
	}

	return 0;
}
#endif /* CONFIG_PM_SLEEP */

void virtsnd_pcm_event(struct virtio_snd *snd, struct virtio_snd_event *event)
{
	struct virtio_pcm_substream *substream;
	unsigned int sid = le32_to_cpu(event->data);

	if (sid >= snd->nsubstreams)
		return;

	substream = &snd->substreams[sid];

	switch (le32_to_cpu(event->hdr.code)) {
	case VIRTIO_SND_EVT_PCM_PERIOD_ELAPSED: {
		/* TODO: deal with shmem elapsed period */
		break;
	}
	case VIRTIO_SND_EVT_PCM_XRUN: {
		if (atomic_read(&substream->xfer_enabled))
			atomic_set(&substream->xfer_xrun, 1);
		break;
	}
	}
}
