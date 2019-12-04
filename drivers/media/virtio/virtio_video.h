/* SPDX-License-Identifier: GPL-2.0+ */
/* Common header for virtio video driver.
 *
 * Copyright 2019 OpenSynergy GmbH.
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

#ifndef _VIRTIO_VIDEO_H
#define _VIRTIO_VIDEO_H

#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/virtio_video.h>
#include <linux/list.h>
#include <media/v4l2-device.h>
#include <media/v4l2-mem2mem.h>
#include <media/v4l2-ctrls.h>

#define DRIVER_NAME "virtio-video"

#ifndef VIRTIO_ID_VIDEO
#define VIRTIO_ID_VIDEO 29
#endif

enum video_pin_type {
	VIDEO_PIN_TYPE_INPUT = 0,
	VIDEO_PIN_TYPE_OUTPUT,
};

enum video_params_scope {
	VIDEO_PARAMS_SCOPE_STREAM = 0,
	VIDEO_PARAMS_SCOPE_DEVICE,
};

#define MIN_BUFS_MIN 0
#define MIN_BUFS_MAX 32
#define MIN_BUFS_STEP 1
#define MIN_BUFS_DEF 1

struct video_frame_rate {
	unsigned int min_rate;
	unsigned int max_rate;
	unsigned int step;
};

struct video_frame_size {
	unsigned int min_width;
	unsigned int max_width;
	unsigned int step_width;
	unsigned int min_height;
	unsigned int max_height;
	unsigned int step_height;
	unsigned int num_rates;
	struct video_frame_rate *frame_rates;
};

struct video_pix_format {
	uint32_t fourcc_format;
	unsigned int num_sizes;
	struct video_frame_size *frame_sizes;
};

struct video_frame_format {
	int pin_type; /* VIRTIO_VIDEO_PIN_ */
	unsigned int num_formats;
	struct video_pix_format *pix_formats;
};

struct video_control {
	uint32_t control_type;
	uint32_t step;
	uint64_t min;
	uint64_t max;
	uint64_t def;
};

struct video_controls {
	unsigned int num_controls;
	struct video_control *control;
};

struct video_capability {
	struct list_head caps_list_entry;
	int cap_type; /* VIRTIO_VIDEO_CAP_ */
	unsigned int cap_id;
	union {
		struct video_frame_format frame_format;
		struct video_controls controls;
	} u;
};

struct virtio_video;
struct virtio_video_vbuffer;

typedef void (*virtio_video_resp_cb)(struct virtio_video *vv,
				     struct virtio_video_vbuffer *vbuf);

struct virtio_video_vbuffer {
	char *buf;
	int size;

	void *data_buf;
	uint32_t data_size;

	char *resp_buf;
	int resp_size;

	void *priv;
	virtio_video_resp_cb resp_cb;

	struct list_head list;
};

struct virtio_video_queue {
	struct virtqueue *vq;
	spinlock_t qlock;
	wait_queue_head_t ack_queue;
	struct work_struct dequeue_work;
};

struct virtio_video {
	struct v4l2_device v4l2_dev;
	int instance;

	struct virtio_device *vdev;
	struct virtio_video_queue ctrlq;
	struct virtio_video_queue eventq;
	wait_queue_head_t wq;
	bool vq_ready;

	struct kmem_cache *vbufs;

	struct idr resource_idr;
	spinlock_t resource_idr_lock;
	struct idr stream_idr;
	spinlock_t stream_idr_lock;

	uint32_t num_devices;
	uint32_t funcs_size;
	bool got_funcs;

	bool has_iommu;
	struct list_head devices_list;

	int debug;
};

struct video_plane_format {
	uint32_t channel;
	uint32_t plane_size;
	uint32_t stride;
	uint32_t padding;
};

struct video_format_info {
	unsigned int frame_rate;
	unsigned int frame_width;
	unsigned int frame_height;
	unsigned int min_buffers;
	uint32_t fourcc_format;
	uint32_t num_planes;
	struct video_plane_format plane_format[VIRTIO_VIDEO_MAX_PLANES];
	bool is_updated;
};

enum video_stream_state {
	STREAM_STATE_IDLE = 0,
	STREAM_STATE_INIT,
	STREAM_STATE_METADATA, /* specific to decoder */
	STREAM_STATE_RUNNING,
	STREAM_STATE_DRAIN,
	STREAM_STATE_STOPPED,
	STREAM_STATE_RESET, /* specific to encoder */
};

struct virtio_video_device {
	struct virtio_video *vv;
	struct video_device video_dev;
	struct mutex video_dev_mutex;

	struct v4l2_m2m_dev *m2m_dev;

	struct workqueue_struct *workqueue;

	struct list_head devices_list_entry;
	/* VIRTIO_VIDEO_FUNC_ */
	int type;
	unsigned int id;
	/* List of control capabilities */
	struct list_head ctrl_caps_list;
	/* List of frame formats capabilities */
	struct list_head fmt_caps_list;

	/* The following 2 arrays contain pointers to pixel formats that are
	 * stored in 'fmt_caps_list' (as a part of the 'video_frame_format'
	 * structure). They are necessary to simplify indexing
	 * through pixel formats in the implementation of ENUM_FMT callbacks
	 */

	/* Array of pointers to pixel formats of CAPTURE pin */
	unsigned int num_capture_formats;
	struct video_pix_format **capture_fmts;

	/* Array of pointers to pixel formats of OUTPUT pin */
	unsigned int num_output_formats;
	struct video_pix_format **output_fmts;

	struct video_format_info in_info;
	struct video_format_info out_info;
};

int virtio_video_alloc_vbufs(struct virtio_video *vv);
void virtio_video_free_vbufs(struct virtio_video *vv);
int virtio_video_alloc_events(struct virtio_video *vv, size_t num);

int virtio_video_devices_init(struct virtio_video *vv, void *funcs_buf);
void virtio_video_devices_deinit(struct virtio_video *vv);

struct virtio_video_stream {
	uint32_t stream_id;
	enum video_stream_state state;
	struct video_device *video_dev;
	struct v4l2_fh fh;
	struct mutex vq_mutex;
	struct v4l2_ctrl_handler ctrl_handler;
	struct video_format_info in_info;
	struct video_format_info out_info;
	bool src_cleared;
	bool dst_cleared;
	bool mark_last_buffer_pending;
	bool check_drain_sequence_pending;
	struct work_struct work;
	struct video_frame_size *current_frame_size;
};

struct virtio_video_buffer {
	struct v4l2_m2m_buffer v4l2_m2m_vb;
	uint32_t resource_id;
	bool detached;
	bool queued;
};

static inline struct virtio_video_device *
to_virtio_vd(struct video_device *video_dev)
{
	return container_of(video_dev, struct virtio_video_device,
			 video_dev);
}

static inline struct virtio_video_stream *file2stream(struct file *file)
{
	return container_of(file->private_data, struct virtio_video_stream, fh);
}

static inline struct virtio_video_stream *ctrl2stream(struct v4l2_ctrl *ctrl)
{
	return container_of(ctrl->handler, struct virtio_video_stream,
			    ctrl_handler);
}

static inline struct virtio_video_stream *work2stream(struct work_struct *work)
{
	return container_of(work, struct virtio_video_stream, work);
}

static inline struct virtio_video_buffer *to_virtio_vb(struct vb2_buffer *vb)
{
	struct vb2_v4l2_buffer *v4l2_vb = to_vb2_v4l2_buffer(vb);

	return container_of(v4l2_vb, struct virtio_video_buffer,
			    v4l2_m2m_vb.vb);
}

void virtio_video_stream_id_get(struct virtio_video *vv,
				struct virtio_video_stream *stream,
				uint32_t *id);
void virtio_video_stream_id_put(struct virtio_video *vv, uint32_t id);
void virtio_video_resource_id_get(struct virtio_video *vv, uint32_t *id);
void virtio_video_resource_id_put(struct virtio_video *vv, uint32_t id);

int virtio_video_req_stream_create(struct virtio_video *vv,
				   uint32_t function_id, uint32_t stream_id,
				   const char *name);
int virtio_video_req_stream_destroy(struct virtio_video *vv,
				    uint32_t function_id, uint32_t stream_id);
int virtio_video_req_stream_start(struct virtio_video *vv,
				  uint32_t function_id, uint32_t stream_id);
int virtio_video_req_stream_stop(struct virtio_video *vv,
				 uint32_t function_id,
				 struct virtio_video_stream *stream);
int virtio_video_req_stream_drain(struct virtio_video *vv,
				  uint32_t function_id, uint32_t stream_id);
int virtio_video_req_resource_create(struct virtio_video *vv,
				     uint32_t function_id, uint32_t stream_id,
				     uint32_t resource_id);
int virtio_video_req_resource_destroy(struct virtio_video *vv,
				      uint32_t function_id, uint32_t stream_id,
				      uint32_t resource_id);
int virtio_video_req_resource_queue(struct virtio_video *vv,
				uint32_t function_id, uint32_t stream_id,
				struct virtio_video_buffer *virtio_vb,
				uint32_t data_size[],
				uint8_t num_data_size, bool is_in);
int virtio_video_req_queue_clear(struct virtio_video *vv, uint32_t function_id,
				 struct virtio_video_stream *stream,
				 bool is_in);
int
virtio_video_req_resource_attach_backing(struct virtio_video *vv,
					 uint32_t function_id,
					 uint32_t stream_id,
					 uint32_t resource_id,
					 struct virtio_video_mem_entry *ents,
					 uint32_t nents);
int
virtio_video_req_resource_detach_backing(struct virtio_video *vv,
					 uint32_t function_id,
					 uint32_t stream_id,
					 struct virtio_video_buffer *virtio_vb);
int virtio_video_req_funcs(struct virtio_video *vv, void *resp_buf,
			   size_t resp_size);
int virtio_video_req_set_params(struct virtio_video *vv, uint32_t function_id,
					struct video_format_info *format_info,
					enum video_pin_type pin_type,
					enum video_params_scope scope,
					struct virtio_video_stream *stream);
int virtio_video_req_get_params(struct virtio_video *vv, uint32_t function_id,
					enum video_pin_type pin_type,
					enum video_params_scope scope,
					struct virtio_video_stream *stream);
int virtio_video_req_set_control(struct virtio_video *vv,
				 uint32_t function_id, uint32_t stream_id,
				 uint32_t control, uint32_t val);

void virtio_video_queue_res_chg_event(struct virtio_video_stream *stream);
void virtio_video_queue_eos_event(struct virtio_video_stream *stream);
void virtio_video_ctrl_ack(struct virtqueue *vq);
void virtio_video_event_ack(struct virtqueue *vq);
void virtio_video_dequeue_ctrl_func(struct work_struct *work);
void virtio_video_dequeue_event_func(struct work_struct *work);
void virtio_video_buf_done(struct virtio_video_buffer *virtio_vb,
			   uint32_t flags, uint64_t timestamp, uint32_t size);
void virtio_video_mark_drain_complete(struct virtio_video_stream *stream,
				      struct vb2_v4l2_buffer *v4l2_vb);

void virtio_video_free_caps_list(struct list_head *caps_list);
size_t virtio_video_parse_virtio_function(void *func_buf,
					  struct virtio_video_device *vvd);
void virtio_video_clean_virtio_function(struct virtio_video_device *vvd);

uint32_t virtio_video_format_to_v4l2(uint32_t pixel_format);
uint32_t virtio_video_v4l2_fourcc_to_virtio(uint32_t fourcc);
uint32_t virtio_video_control_to_v4l2(uint32_t control_type);
uint32_t virtio_video_profile_to_v4l2(uint32_t profile);
uint32_t virtio_video_level_to_v4l2(uint32_t level);
uint32_t virtio_video_v4l2_control_to_virtio(uint32_t v4l2_control);
uint32_t virtio_video_v4l2_profile_to_virtio(uint32_t v4l2_profile);
uint32_t virtio_video_v4l2_level_to_virtio(uint32_t v4l2_level);

#endif /* _VIRTIO_VIDEO_H */
