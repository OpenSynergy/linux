/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Virtio Video Device
 *
 * This header is BSD licensed so anyone can use the definitions
 * to implement compatible drivers/servers:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of IBM nor the names of its contributors
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

#ifndef _UAPI_VIRTIO_VIDEO_H
#define	_UAPI_VIRTIO_VIDEO_H

#include <linux/types.h>
#include <linux/virtio_config.h>

/* Maximum number of planes associated with a resource. */
#define VIRTIO_VIDEO_MAX_PLANES 8

/* Maximum size of get params response */
#define VIRTIO_VIDEO_MAXSIZE_GET_PARAMS 1024

enum virtio_video_func_type {
	VIRTIO_VIDEO_FUNC_UNDEFINED = 0,

	VIRTIO_VIDEO_FUNC_ENCODER = 0x0100,
	VIRTIO_VIDEO_FUNC_DECODER,
	VIRTIO_VIDEO_FUNC_PROCESSOR,
	VIRTIO_VIDEO_FUNC_CAPTURE,
	VIRTIO_VIDEO_FUNC_OUTPUT,
};

enum virtio_video_ctrl_type {
	VIRTIO_VIDEO_CTRL_UNDEFINED = 0,

	/* request */
	VIRTIO_VIDEO_T_GET_FUNCS = 0x0100,
	VIRTIO_VIDEO_T_STREAM_CREATE,
	VIRTIO_VIDEO_T_STREAM_DESTROY,
	VIRTIO_VIDEO_T_STREAM_START,
	VIRTIO_VIDEO_T_STREAM_STOP,
	VIRTIO_VIDEO_T_STREAM_DRAIN,
	VIRTIO_VIDEO_T_RESOURCE_CREATE,
	VIRTIO_VIDEO_T_RESOURCE_DESTROY,
	VIRTIO_VIDEO_T_RESOURCE_ATTACH_BACKING,
	VIRTIO_VIDEO_T_RESOURCE_DETACH_BACKING,
	VIRTIO_VIDEO_T_RESOURCE_QUEUE,
	VIRTIO_VIDEO_T_QUEUE_CLEAR,
	VIRTIO_VIDEO_T_SET_PARAMS,
	VIRTIO_VIDEO_T_GET_PARAMS,
	VIRTIO_VIDEO_T_SET_CONTROL,

	/* response */
	VIRTIO_VIDEO_S_OK = 0x0200,
	VIRTIO_VIDEO_S_OK_RESOURCE_QUEUE,
	VIRTIO_VIDEO_S_OK_GET_PARAMS,

	VIRTIO_VIDEO_S_ERR_UNSPEC = 0x0300,
	VIRTIO_VIDEO_S_ERR_OUT_OF_MEMORY,
	VIRTIO_VIDEO_S_ERR_INVALID_FUNCTION_ID,
	VIRTIO_VIDEO_S_ERR_INVALID_RESOURCE_ID,
	VIRTIO_VIDEO_S_ERR_INVALID_STREAM_ID,
	VIRTIO_VIDEO_S_ERR_INVALID_PARAMETER,
};

enum virtio_video_event_type {
	VIRTIO_VIDEO_EVENT_T_UNDEFINED = 0,

	VIRTIO_VIDEO_EVENT_T_RESOLUTION_CHANGED = 0x0100,
	VIRTIO_VIDEO_EVENT_T_CONFIGURED,
};

enum virtio_video_buffer_flag {
	VIRTIO_VIDEO_BUFFER_F_ERR	= 0x0001,
	VIRTIO_VIDEO_BUFFER_F_EOS	= 0x0002,
	VIRTIO_VIDEO_BUFFER_IFRAME	= 0x0004,
	VIRTIO_VIDEO_BUFFER_PFRAME	= 0x0008,
	VIRTIO_VIDEO_BUFFER_BFRAME	= 0x0010,
};

enum virtio_video_desc_type {
	VIRTIO_VIDEO_DESC_UNDEFINED = 0,

	VIRTIO_VIDEO_DESC_FRAME_RATE = 0x0100,
	VIRTIO_VIDEO_DESC_FRAME_SIZE,
	VIRTIO_VIDEO_DESC_PIX_FORMAT,
	VIRTIO_VIDEO_DESC_PLANE_FORMAT,
	VIRTIO_VIDEO_DESC_CONTROL,
	VIRTIO_VIDEO_DESC_EXTRAS,
	VIRTIO_VIDEO_DESC_CAP,
	VIRTIO_VIDEO_DESC_FUNC,
	VIRTIO_VIDEO_DESC_PARAMS,
	VIRTIO_VIDEO_DESC_DEFAULTS,
};

enum virtio_video_pin_type {
	VIRTIO_VIDEO_PIN_UNDEFINED = 0,

	VIRTIO_VIDEO_PIN_INPUT = 0x0100,
	VIRTIO_VIDEO_PIN_OUTPUT,
};

enum virtio_video_channel_type {
	VIRTIO_VIDEO_CHANNEL_UNDEFINED = 0,

	VIRTIO_VIDEO_CHANNEL_Y = 0x0100,
	VIRTIO_VIDEO_CHANNEL_U,
	VIRTIO_VIDEO_CHANNEL_V,
	VIRTIO_VIDEO_CHANNEL_UV,
	VIRTIO_VIDEO_CHANNEL_VU,
	VIRTIO_VIDEO_CHANNEL_YUV,
	VIRTIO_VIDEO_CHANNEL_YVU,
	VIRTIO_VIDEO_CHANNEL_BGR,
	VIRTIO_VIDEO_CHANNEL_BGRX,
};

enum virtio_video_control_type {
	VIRTIO_VIDEO_CONTROL_UNDEFINED = 0,

	VIRTIO_VIDEO_CONTROL_BITRATE = 0x100,
	VIRTIO_VIDEO_CONTROL_PROFILE,
	VIRTIO_VIDEO_CONTROL_LEVEL,
};

enum virtio_video_scope_type {
	VIRTIO_VIDEO_SCOPE_UNDEFINED = 0,

	VIRTIO_VIDEO_SCOPE_GLOBAL = 0x0100,
	VIRTIO_VIDEO_SCOPE_STREAM,
};

enum virtio_video_cap_type {
	VIRTIO_VIDEO_CAP_UNDEFINED = 0,

	VIRTIO_VIDEO_CAP_PIN_FORMATS = 0x0100,
	VIRTIO_VIDEO_CAP_CONTROL,
};

struct virtio_video_ctrl_hdr {
	__le32 type;
	__le32 stream_id;
	__le32 function_id;
	__u8 padding[4];
};

struct virtio_video_desc {
	__le32 type; /* One of VIRTIO_VIDEO_DESC_* types */
	__le16 length;
	__u8 padding[2];
};

struct virtio_video_frame_rate {
	struct virtio_video_desc desc;
	__le32 min_rate;
	__le32 max_rate;
	__le32 step;
	__u8 padding[4];
};

struct virtio_video_frame_size {
	struct virtio_video_desc desc;
	__le32 min_width;
	__le32 max_width;
	__le32 step_width;
	__le32 min_height;
	__le32 max_height;
	__le32 step_height;
	__le32 num_rates;
	__u8 padding[4];
	/* Followed by struct virtio_video_frame_rate frame_rates[]; */
};

struct virtio_video_pix_format {
	struct virtio_video_desc desc;
	__le32 pixel_format;
	__le32 num_sizes;
	/* Followed by struct virtio_video_frame_size frame_sizes[]; */
};

struct virtio_video_frame_format {
	__le32 pin_type; /* One of VIRTIO_VIDEO_PIN_* types */
	__le32 num_formats;
	/* Followed by struct virtio_video_pix_format pix_formats[]; */
};

struct virtio_video_extras {
	struct virtio_video_desc desc;
};

struct virtio_video_plane_format {
	struct virtio_video_desc desc;
	__le32 channel; /* One of VIRTIO_VIDEO_CHANNEL_* types */
	__le32 plane_size;
	__le32 stride;
	__le32 padding;
};

struct virtio_video_control {
	struct virtio_video_desc desc;
	__le32 control_type;  /* One of VIRTO_VIDEO_CONTROL_* types */
	__le32 step;
	__le64 min;
	__le64 max;
	__le64 def;
};

struct virtio_video_controls {
	__le32 num_controls;
	__u8 padding[4];
	/* Followed by struct virtio_video_control control[]; */
};

struct virtio_video_capability {
	struct virtio_video_desc desc;
	__le32 cap_type; /* One of VIRTIO_VIDEO_CAP_* types */
	__le32 cap_id;
	union {
		struct virtio_video_frame_format frame_format;
		struct virtio_video_controls controls;
	} u;
};

struct virtio_video_params {
	struct virtio_video_desc desc;
	__le32 pin_type; /* One of VIRTIO_VIDEO_PIN_* types */
	__le32 scope; /* One of VIRTIO_VIDEO_SCOPE_* types */
	__le32 frame_rate;
	__le32 frame_width;
	__le32 frame_height;
	__le32 pixel_format;
	__le32 min_buffers;
	__le32 num_planes;
	struct virtio_video_plane_format plane_formats[VIRTIO_VIDEO_MAX_PLANES];
	struct virtio_video_extras extra;

};

struct virtio_video_function {
	struct virtio_video_desc desc;
	__le32 function_type; /* One of VIRTIO_VIDEO_FUNC_* types */
	__le32 function_id;
	struct virtio_video_params in_params;
	struct virtio_video_params out_params;
	__le32 num_caps;
	__u8 padding[4];
	/* Followed by struct virtio_video_capability video_caps[]; */
};

struct virtio_video_config {
	__u32 num_functions;
	__u32 total_functions_size;
};

struct virtio_video_mem_entry {
	__le64 addr;
	__le32 length;
	__u8 padding[4];
};

struct virtio_video_event {
	__le32 event_type;
	__le32 function_id;
	__le32 stream_id;
	__u8 padding[4];
};

/* VIRTIO_VIDEO_T_GET_FUNCS */
struct virtio_video_get_functions {
	struct virtio_video_ctrl_hdr hdr;
};

/* VIRTIO_VIDEO_T_STREAM_CREATE */
struct virtio_video_stream_create {
	struct virtio_video_ctrl_hdr hdr;
	char debug_name[64];
};

/* VIRTIO_VIDEO_T_STREAM_DESTROY */
struct virtio_video_stream_destroy {
	struct virtio_video_ctrl_hdr hdr;
};

/* VIRTIO_VIDEO_T_STREAM_START */
struct virtio_video_stream_start {
	struct virtio_video_ctrl_hdr hdr;
};

/* VIRTIO_VIDEO_T_STREAM_STOP */
struct virtio_video_stream_stop {
	struct virtio_video_ctrl_hdr hdr;
};

/* VIRTIO_VIDEO_T_STREAM_DRAIN */
struct virtio_video_stream_drain {
	struct virtio_video_ctrl_hdr hdr;
};

/* VIRTIO_VIDEO_T_RESOURCE_CREATE */
struct virtio_video_resource_create {
	struct virtio_video_ctrl_hdr hdr;
	__le32 resource_id;
	__u8 padding[4];
};

/* VIRTIO_VIDEO_T_RESOURCE_DESTROY */
struct virtio_video_resource_destroy {
	struct virtio_video_ctrl_hdr hdr;
	__le32 resource_id;
	__u8 padding[4];
};

/* VIRTIO_VIDEO_T_RESOURCE_ATTACH_BACKING */
struct virtio_video_resource_attach_backing {
	struct virtio_video_ctrl_hdr hdr;
	__le32 resource_id;
	__le32 nr_entries;
};

/* VIRTIO_VIDEO_T_RESOURCE_DETACH_BACKING*/
struct virtio_video_resource_detach_backing {
	struct virtio_video_ctrl_hdr hdr;
	__le32 resource_id;
	__u8 padding[4];
};

/* VIRTIO_VIDEO_T_RESOURCE_QUEUE */
struct virtio_video_resource_queue {
	struct virtio_video_ctrl_hdr hdr;
	__le64 timestamp;
	__le32 resource_id;
	__le32 pin_type;
	__le32 data_size[VIRTIO_VIDEO_MAX_PLANES];
	__u8 nr_data_size;
	__u8 padding[7];
};

/* VIRTIO_VIDEO_QUEUE_CLEAR */
struct virtio_video_queue_clear {
	struct virtio_video_ctrl_hdr hdr;
	__le32 pin_type;
	__u8 padding[4];
};

/* VIRTIO_VIDEO_T_SET_PARAMS */
struct virtio_video_set_params {
	struct virtio_video_ctrl_hdr hdr;
	struct virtio_video_params params;
};

/* VIRTIO_VIDEO_T_GET_PARAMS */
struct virtio_video_get_params {
	struct virtio_video_ctrl_hdr hdr;
	__le32 pin_type; /* One of VIRTIO_VIDEO_PIN_* types */
	__le32 scope; /* One of VIRTIO_VIDEO_SCOPE_* types */
};

struct virtio_video_resource_queue_resp {
	struct virtio_video_ctrl_hdr hdr;
	__le64 timestamp;
	__le32 flags; /* One of VIRTIO_VIDEO_BUFFER_* flags */
	__le32 size;  /* Encoded size */
};

struct virtio_video_get_params_resp {
	struct virtio_video_ctrl_hdr hdr;
	struct virtio_video_params params;
};

/* VIRTIO_VIDEO_T_SET_CONTROL */
struct virtio_video_set_control {
	struct virtio_video_ctrl_hdr hdr;
	__le64 val;
	__le32 type;  /* One of VIRTO_VIDEO_CONTROL_* types */
	__u8 padding[4];
};

enum virtio_video_pix_format_type {
	VIRTIO_VIDEO_PIX_FMT_UNKNOWN = 0,

	VIRTIO_VIDEO_PIX_FMT_H264 = 0x100,
	VIRTIO_VIDEO_PIX_FMT_NV12,
	VIRTIO_VIDEO_PIX_FMT_NV21,
	VIRTIO_VIDEO_PIX_FMT_I420,
	VIRTIO_VIDEO_PIX_FMT_I422,
	VIRTIO_VIDEO_PIX_FMT_XBGR,
	VIRTIO_VIDEO_PIX_FMT_H265,
	VIRTIO_VIDEO_PIX_FMT_MPEG4,
	VIRTIO_VIDEO_PIX_FMT_MPEG2,
};

enum virtio_video_profile_type {
	VIRTIO_MPEG_VIDEO_H264_PROFILE_UNDEFINED = 0,

	VIRTIO_MPEG_VIDEO_H264_PROFILE_BASELINE	= 0x100,
	VIRTIO_MPEG_VIDEO_H264_PROFILE_CONSTRAINED_BASELINE,
	VIRTIO_MPEG_VIDEO_H264_PROFILE_MAIN,
	VIRTIO_MPEG_VIDEO_H264_PROFILE_EXTENDED,
	VIRTIO_MPEG_VIDEO_H264_PROFILE_HIGH,
	VIRTIO_MPEG_VIDEO_H264_PROFILE_HIGH_10,
	VIRTIO_MPEG_VIDEO_H264_PROFILE_HIGH_422,
	VIRTIO_MPEG_VIDEO_H264_PROFILE_HIGH_444_PREDICTIVE,
	VIRTIO_MPEG_VIDEO_H264_PROFILE_HIGH_10_INTRA,
	VIRTIO_MPEG_VIDEO_H264_PROFILE_HIGH_422_INTRA,
	VIRTIO_MPEG_VIDEO_H264_PROFILE_HIGH_444_INTRA,
	VIRTIO_MPEG_VIDEO_H264_PROFILE_CAVLC_444_INTRA,
	VIRTIO_MPEG_VIDEO_H264_PROFILE_SCALABLE_BASELINE,
	VIRTIO_MPEG_VIDEO_H264_PROFILE_SCALABLE_HIGH,
	VIRTIO_MPEG_VIDEO_H264_PROFILE_SCALABLE_HIGH_INTRA,
	VIRTIO_MPEG_VIDEO_H264_PROFILE_STEREO_HIGH,
	VIRTIO_MPEG_VIDEO_H264_PROFILE_MULTIVIEW_HIGH,
};

enum virtio_video_level_type {
	VIRTIO_MPEG_VIDEO_H264_LEVEL_UNDEFINED = 0,

	VIRTIO_MPEG_VIDEO_H264_LEVEL_1_0 = 0x100,
	VIRTIO_MPEG_VIDEO_H264_LEVEL_1B,
	VIRTIO_MPEG_VIDEO_H264_LEVEL_1_1,
	VIRTIO_MPEG_VIDEO_H264_LEVEL_1_2,
	VIRTIO_MPEG_VIDEO_H264_LEVEL_1_3,
	VIRTIO_MPEG_VIDEO_H264_LEVEL_2_0,
	VIRTIO_MPEG_VIDEO_H264_LEVEL_2_1,
	VIRTIO_MPEG_VIDEO_H264_LEVEL_2_2,
	VIRTIO_MPEG_VIDEO_H264_LEVEL_3_0,
	VIRTIO_MPEG_VIDEO_H264_LEVEL_3_1,
	VIRTIO_MPEG_VIDEO_H264_LEVEL_3_2,
	VIRTIO_MPEG_VIDEO_H264_LEVEL_4_0,
	VIRTIO_MPEG_VIDEO_H264_LEVEL_4_1,
	VIRTIO_MPEG_VIDEO_H264_LEVEL_4_2,
	VIRTIO_MPEG_VIDEO_H264_LEVEL_5_0,
	VIRTIO_MPEG_VIDEO_H264_LEVEL_5_1,
};

#endif /* _UAPI_VIRTIO_VIDEO_H */
