/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef VIRTIO_SND_IF_H
#define VIRTIO_SND_IF_H
/*
 * Copyright (C) 2019  OpenSynergy GmbH
 *
 * This header is BSD licensed so anyone can use the definitions to
 * implement compatible drivers/servers.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of OpenSynergy GmbH nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL IBM OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <linux/types.h>
#include <linux/virtio_types.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>

/*******************************************************************************
 * COMMON DEFINITIONS
 */

/* a configuration space */
struct virtio_snd_config {
	/* maximum # of available virtual queues (including the control queue)
	 */
	__virtio32 nqueues;
};

enum {
	/* the base function request types */
	VIRTIO_SND_R_BASE_GET_CFG = 0,

	/* the PCM function request types */
	VIRTIO_SND_R_PCM_SET_QUEUE = 0x0100,
	VIRTIO_SND_R_PCM_SET_FORMAT,
	VIRTIO_SND_R_PCM_PREPARE,
	VIRTIO_SND_R_PCM_START,
	VIRTIO_SND_R_PCM_STOP,
	VIRTIO_SND_R_PCM_PAUSE,
	VIRTIO_SND_R_PCM_UNPAUSE,
	VIRTIO_SND_R_PCM_QUERY_CHMAP,
	VIRTIO_SND_R_PCM_USE_CHMAP,

	/* response status codes */
	VIRTIO_SND_S_OK = 0x8000,
	VIRTIO_SND_S_ENOTSUPPORTED,
	VIRTIO_SND_S_EINVALID,
	VIRTIO_SND_S_EIO
};

/* a generic control header */
struct virtio_snd_hdr {
	__virtio32 code;
};

/* supported descriptor types */
enum {
	VIRTIO_SND_DESC_PCM = 0,
	VIRTIO_SND_DESC_PCM_STREAM
};

/* a generic descriptor */
struct virtio_snd_desc {
	__u8 length;
	__u8 type;

	__u16 padding;
};

/*******************************************************************************
 * BASE FUNCTION DEFINITIONS
 */

/* a maximum possible configuration data size (in bytes) */
#define VIRTIO_SND_BASE_CFG_MAX_SIZE	1024

/* a response containing device configuration */
struct virtio_snd_base_configuration {
	struct virtio_snd_hdr hdr;
	/* size in bytes of configuration data */
	__virtio32 length;
	/* configuration data */
	__u8 data[VIRTIO_SND_BASE_CFG_MAX_SIZE];
};

/*******************************************************************************
 * PCM FUNCTION DEFINITIONS
 */

/* supported PCM stream types */
enum {
	VIRTIO_SND_PCM_T_PLAYBACK = 0,
	VIRTIO_SND_PCM_T_CAPTURE
};

/* supported PCM sample formats */
enum {
	VIRTIO_SND_PCM_FMT_S8 = 0,
	VIRTIO_SND_PCM_FMT_U8,
	VIRTIO_SND_PCM_FMT_S16,
	VIRTIO_SND_PCM_FMT_U16,
	VIRTIO_SND_PCM_FMT_S24,
	VIRTIO_SND_PCM_FMT_U24,
	VIRTIO_SND_PCM_FMT_S32,
	VIRTIO_SND_PCM_FMT_U32,
	VIRTIO_SND_PCM_FMT_FLOAT,
	VIRTIO_SND_PCM_FMT_FLOAT64,
	VIRTIO_SND_PCM_FMT_S20,
	VIRTIO_SND_PCM_FMT_U20,
	VIRTIO_SND_PCM_FMT_S24_3,
	VIRTIO_SND_PCM_FMT_U24_3,
	VIRTIO_SND_PCM_FMT_S20_3,
	VIRTIO_SND_PCM_FMT_U20_3,
	VIRTIO_SND_PCM_FMT_S18_3,
	VIRTIO_SND_PCM_FMT_U18_3
};

#define VIRTIO_SND_PCM_FMTBIT(bit) \
	(1U << VIRTIO_SND_PCM_FMT_ ## bit)

enum {
	VIRTIO_SND_PCM_FMTBIT_S8 = VIRTIO_SND_PCM_FMTBIT(S8),
	VIRTIO_SND_PCM_FMTBIT_U8 = VIRTIO_SND_PCM_FMTBIT(U8),
	VIRTIO_SND_PCM_FMTBIT_S16 = VIRTIO_SND_PCM_FMTBIT(S16),
	VIRTIO_SND_PCM_FMTBIT_U16 = VIRTIO_SND_PCM_FMTBIT(U16),
	VIRTIO_SND_PCM_FMTBIT_S24 = VIRTIO_SND_PCM_FMTBIT(S24),
	VIRTIO_SND_PCM_FMTBIT_U24 = VIRTIO_SND_PCM_FMTBIT(U24),
	VIRTIO_SND_PCM_FMTBIT_S32 = VIRTIO_SND_PCM_FMTBIT(S32),
	VIRTIO_SND_PCM_FMTBIT_U32 = VIRTIO_SND_PCM_FMTBIT(U32),
	VIRTIO_SND_PCM_FMTBIT_FLOAT = VIRTIO_SND_PCM_FMTBIT(FLOAT),
	VIRTIO_SND_PCM_FMTBIT_FLOAT64 = VIRTIO_SND_PCM_FMTBIT(FLOAT64),
	VIRTIO_SND_PCM_FMTBIT_S20 = VIRTIO_SND_PCM_FMTBIT(S20),
	VIRTIO_SND_PCM_FMTBIT_U20 = VIRTIO_SND_PCM_FMTBIT(U20),
	VIRTIO_SND_PCM_FMTBIT_S24_3 = VIRTIO_SND_PCM_FMTBIT(S24_3),
	VIRTIO_SND_PCM_FMTBIT_U24_3 = VIRTIO_SND_PCM_FMTBIT(U24_3),
	VIRTIO_SND_PCM_FMTBIT_S20_3 = VIRTIO_SND_PCM_FMTBIT(S20_3),
	VIRTIO_SND_PCM_FMTBIT_U20_3 = VIRTIO_SND_PCM_FMTBIT(U20_3),
	VIRTIO_SND_PCM_FMTBIT_S18_3 = VIRTIO_SND_PCM_FMTBIT(S18_3),
	VIRTIO_SND_PCM_FMTBIT_U18_3 = VIRTIO_SND_PCM_FMTBIT(U18_3)
};

/* supported PCM frame rates */
enum {
	VIRTIO_SND_PCM_RATE_8000 = 0,
	VIRTIO_SND_PCM_RATE_11025,
	VIRTIO_SND_PCM_RATE_16000,
	VIRTIO_SND_PCM_RATE_22050,
	VIRTIO_SND_PCM_RATE_32000,
	VIRTIO_SND_PCM_RATE_44100,
	VIRTIO_SND_PCM_RATE_48000,
	VIRTIO_SND_PCM_RATE_64000,
	VIRTIO_SND_PCM_RATE_88200,
	VIRTIO_SND_PCM_RATE_96000,
	VIRTIO_SND_PCM_RATE_176400,
	VIRTIO_SND_PCM_RATE_192000
};

#define VIRTIO_SND_PCM_RATEBIT(bit) \
	(1U << VIRTIO_SND_PCM_RATE_ ## bit)

enum {
	VIRTIO_SND_PCM_RATEBIT_8000 = VIRTIO_SND_PCM_RATEBIT(8000),
	VIRTIO_SND_PCM_RATEBIT_11025 = VIRTIO_SND_PCM_RATEBIT(11025),
	VIRTIO_SND_PCM_RATEBIT_16000 = VIRTIO_SND_PCM_RATEBIT(16000),
	VIRTIO_SND_PCM_RATEBIT_22050 = VIRTIO_SND_PCM_RATEBIT(22050),
	VIRTIO_SND_PCM_RATEBIT_32000 = VIRTIO_SND_PCM_RATEBIT(32000),
	VIRTIO_SND_PCM_RATEBIT_44100 = VIRTIO_SND_PCM_RATEBIT(44100),
	VIRTIO_SND_PCM_RATEBIT_48000 = VIRTIO_SND_PCM_RATEBIT(48000),
	VIRTIO_SND_PCM_RATEBIT_64000 = VIRTIO_SND_PCM_RATEBIT(64000),
	VIRTIO_SND_PCM_RATEBIT_88200 = VIRTIO_SND_PCM_RATEBIT(88200),
	VIRTIO_SND_PCM_RATEBIT_96000 = VIRTIO_SND_PCM_RATEBIT(96000),
	VIRTIO_SND_PCM_RATEBIT_176400 = VIRTIO_SND_PCM_RATEBIT(176400),
	VIRTIO_SND_PCM_RATEBIT_192000 = VIRTIO_SND_PCM_RATEBIT(192000)
};

/* PCM channel map types */
enum {
	/* All channels have fixed channel positions */
	VIRTIO_SND_PCM_CHMAP_FIXED = 0,
	/* All channels are swappable (e.g. {FL/FR/RL/RR} -> {RR/RL/FR/FL}) */
	VIRTIO_SND_PCM_CHMAP_VARIABLE,
	/* Only pair-wise channels are swappable
	 * (e.g. {FL/FR/RL/RR} -> {RL/RR/FL/FR})
	 */
	VIRTIO_SND_PCM_CHMAP_PAIRED
};

/* Standard channel position definition */
enum {
	VIRTIO_SND_PCM_CH_NONE = 0,	/* undefined */
	VIRTIO_SND_PCM_CH_NA,		/* silent */
	VIRTIO_SND_PCM_CH_MONO,		/* mono stream */
	VIRTIO_SND_PCM_CH_FL,		/* front left */
	VIRTIO_SND_PCM_CH_FR,		/* front right */
	VIRTIO_SND_PCM_CH_RL,		/* rear left */
	VIRTIO_SND_PCM_CH_RR,		/* rear right */
	VIRTIO_SND_PCM_CH_FC,		/* front center */
	VIRTIO_SND_PCM_CH_LFE,		/* low frequency (LFE) */
	VIRTIO_SND_PCM_CH_SL,		/* side left */
	VIRTIO_SND_PCM_CH_SR,		/* side right */
	VIRTIO_SND_PCM_CH_RC,		/* rear center */
	VIRTIO_SND_PCM_CH_FLC,		/* front left center */
	VIRTIO_SND_PCM_CH_FRC,		/* front right center */
	VIRTIO_SND_PCM_CH_RLC,		/* rear left center */
	VIRTIO_SND_PCM_CH_RRC,		/* rear right center */
	VIRTIO_SND_PCM_CH_FLW,		/* front left wide */
	VIRTIO_SND_PCM_CH_FRW,		/* front right wide */
	VIRTIO_SND_PCM_CH_FLH,		/* front left high */
	VIRTIO_SND_PCM_CH_FCH,		/* front center high */
	VIRTIO_SND_PCM_CH_FRH,		/* front right high */
	VIRTIO_SND_PCM_CH_TC,		/* top center */
	VIRTIO_SND_PCM_CH_TFL,		/* top front left */
	VIRTIO_SND_PCM_CH_TFR,		/* top front right */
	VIRTIO_SND_PCM_CH_TFC,		/* top front center */
	VIRTIO_SND_PCM_CH_TRL,		/* top rear left */
	VIRTIO_SND_PCM_CH_TRR,		/* top rear right */
	VIRTIO_SND_PCM_CH_TRC,		/* top rear center */
	VIRTIO_SND_PCM_CH_TFLC,		/* top front left center */
	VIRTIO_SND_PCM_CH_TFRC,		/* top front right center */
	VIRTIO_SND_PCM_CH_TSL,		/* top side left */
	VIRTIO_SND_PCM_CH_TSR,		/* top side right */
	VIRTIO_SND_PCM_CH_LLFE,		/* left LFE */
	VIRTIO_SND_PCM_CH_RLFE,		/* right LFE */
	VIRTIO_SND_PCM_CH_BC,		/* bottom center */
	VIRTIO_SND_PCM_CH_BLC,		/* bottom left center */
	VIRTIO_SND_PCM_CH_BRC		/* bottom right center */
};

/* PCM function descriptor */
struct virtio_snd_pcm_desc {
	/* sizeof(struct virtio_snd_pcm_desc) */
	__u8 length;
	/* VIRTIO_SND_DESC_PCM */
	__u8 type;
	/* a PCM function ID (assigned by the device) */
	__u8 pcm_id;
	/* # of PCM stream descriptors in the configuration (one per supported
	 * PCM stream type)
	 */
	__u8 nstreams;
};

/* PCM stream descriptor */
struct virtio_snd_pcm_stream_desc {
	/* sizeof(struct virtio_snd_pcm_stream_desc) */
	__u8 length;
	/* VIRTIO_SND_DESC_PCM_STREAM */
	__u8 type;
	/* a PCM stream type (VIRTIO_SND_PCM_T_*) */
	__u8 stream_type;
	/* # of supported channel maps */
	__u8 nchmaps;
	/* minimum # of supported channels */
	__virtio16 channels_min;
	/* maximum # of supported channels */
	__virtio16 channels_max;
	/* supported sample format bit map (VIRTIO_SND_PCM_FMTBIT_*) */
	__virtio32 formats;
	/* supported frame rate bit map (VIRTIO_SND_PCM_RATEBIT_*) */
	__virtio32 rates;
	/* min size in frames of one audio interval/period */
	__virtio32 period_size_min;
	/* max size in frames of one audio interval/period */
	__virtio32 period_size_max;

	/* explicitly specify supported period sizes in frames */
	/* amount of supported period sizes. Can be 0 when no additional
	 * limitation is required
	 */
	__virtio32 period_size_list_count;
	/* supported periods size in frames */
	__virtio32 period_size_list[32];
};

/* PCM control request header */
struct virtio_snd_pcm_hdr {
	/* VIRTIO_SND_R_PCM_* */
	struct virtio_snd_hdr hdr;
	/* a PCM identifier (assigned in configuration) */
	__u8 pcm_id;
	/* a PCM stream type (VIRTIO_SND_PCM_T_*) */
	__u8 stream_type;

	__u16 padding;
};

/* set a data queue for specified the PCM function instance */
struct virtio_snd_pcm_set_queue {
	/* VIRTIO_SND_R_PCM_SET_QUEUE */
	struct virtio_snd_hdr hdr;
	/* a PCM identifier (assigned in configuration) */
	__u8 pcm_id;
	/* a virtual queue index */
	__u8 queue;

	__u16 padding;
};

/* set PCM stream format */
struct virtio_snd_pcm_set_format {
	/* VIRTIO_SND_R_PCM_SET_FORMAT */
	struct virtio_snd_pcm_hdr hdr;
	/* # of channels */
	__virtio16 channels;
	/* a PCM sample format (VIRTIO_SND_PCM_FMT_*) */
	__virtio16 format;
	/* a PCM frame rate (VIRTIO_SND_PCM_RATE_*) */
	__virtio16 rate;

	__u16 padding;
};

/* a maximum possible number of channels */
#define VIRTIO_SND_PCM_CH_MAX		256

/* query a PCM channel map information */
struct virtio_snd_pcm_query_chmap {
	/* VIRTIO_SND_R_PCM_QUERY_CHMAP */
	struct virtio_snd_hdr hdr;
	/* a PCM identifier (assigned in configuration) */
	__u8 pcm_id;
	/* a PCM stream type (VIRTIO_SND_PCM_T_*) */
	__u8 stream_type;
	/* a PCM channel map identifier [0 ... pcm_stream_desc::nchmaps - 1] */
	__u8 chmap_id;

	__u8 padding;
};

/* request/response containing a PCM channel map information */
struct virtio_snd_pcm_chmap_info {
	/*
	 * request:
	 *   VIRTIO_SND_R_PCM_USE_CHMAP
	 * response:
	 *   VIRTIO_SND_S_*
	 */
	struct virtio_snd_hdr hdr;
	/* a PCM identifier (assigned in configuration) */
	__u8 pcm_id;
	/*
	 * request:
	 *   a PCM stream type (VIRTIO_SND_PCM_T_*)
	 * response:
	 *   a PCM channel map type (VIRTIO_SND_PCM_CHMAP_*)
	 */
	__u8 type;
	/* # of valid entries in the positions array */
	__virtio16 nchannels;
	/* PCM channel positions */
	__u8 positions[VIRTIO_SND_PCM_CH_MAX];
};

/* a PCM stream data transfer */
struct virtio_snd_pcm_xfer {
	/* a start address of data buffer */
	__virtio64 address;
	/* a size in bytes of data buffer */
	__virtio32 length;
	/* a PCM stream type (VIRTIO_SND_PCM_T_*) */
	__u8 stream_type;

	__u8 padding[3];
};

/* response containing a data transfer status */
struct virtio_snd_pcm_status {
	/* status code (VIRTIO_SND_S_*) */
	__virtio32 status;
	/* amount of bytes actually read from/written to a data buffer */
	__virtio32 length;
};

#endif /* VIRTIO_SND_IF_H */
