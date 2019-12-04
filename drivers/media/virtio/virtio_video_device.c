// SPDX-License-Identifier: GPL-2.0+
/* Driver for virtio video device.
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

#include <media/v4l2-event.h>
#include <media/v4l2-ioctl.h>
#include <media/videobuf2-dma-sg.h>

#include "virtio_video.h"
#include "virtio_video_dec.h"
#include "virtio_video_enc.h"

void virtio_video_queue_eos_event(struct virtio_video_stream *stream)
{
	static const struct v4l2_event eos_event = {
		.type = V4L2_EVENT_EOS
	};

	v4l2_event_queue_fh(&stream->fh, &eos_event);
}

void virtio_video_queue_res_chg_event(struct virtio_video_stream *stream)
{
	static const struct v4l2_event ev_src_ch = {
		.type = V4L2_EVENT_SOURCE_CHANGE,
		.u.src_change.changes =
			V4L2_EVENT_SRC_CH_RESOLUTION,
	};

	v4l2_event_queue_fh(&stream->fh, &ev_src_ch);
}

void virtio_video_mark_drain_complete(struct virtio_video_stream *stream,
				      struct vb2_v4l2_buffer *v4l2_vb)
{
	struct vb2_buffer *vb2_buf;

	v4l2_vb->flags |= V4L2_BUF_FLAG_LAST;

	vb2_buf = &v4l2_vb->vb2_buf;
	vb2_buf->planes[0].bytesused = 0;

	v4l2_m2m_buf_done(v4l2_vb, VB2_BUF_STATE_DONE);
	stream->state = STREAM_STATE_STOPPED;
}

void virtio_video_buf_done(struct virtio_video_buffer *virtio_vb,
			   uint32_t flags, uint64_t timestamp, uint32_t size)
{
	int i, ret;
	enum vb2_buffer_state done_state = VB2_BUF_STATE_DONE;
	struct vb2_v4l2_buffer *v4l2_vb = &virtio_vb->v4l2_m2m_vb.vb;
	struct vb2_buffer *vb = &v4l2_vb->vb2_buf;
	struct vb2_queue *vb2_queue = vb->vb2_queue;
	struct virtio_video_stream *stream = vb2_get_drv_priv(vb2_queue);
	struct virtio_video_device *vvd = to_virtio_vd(stream->video_dev);
	struct virtio_video *vv = vvd->vv;
	struct video_format_info *p_info;

	virtio_vb->queued = false;

	if (!V4L2_TYPE_IS_OUTPUT(vb2_queue->type) &&
	    stream->check_drain_sequence_pending) {
		virtio_video_mark_drain_complete(stream, v4l2_vb);
		stream->check_drain_sequence_pending = false;
		return;
	}

	if (flags & VIRTIO_VIDEO_BUFFER_F_ERR)
		done_state = VB2_BUF_STATE_ERROR;

	if (flags & VIRTIO_VIDEO_BUFFER_IFRAME)
		v4l2_vb->flags |= V4L2_BUF_FLAG_KEYFRAME;

	if (flags & VIRTIO_VIDEO_BUFFER_BFRAME)
		v4l2_vb->flags |= V4L2_BUF_FLAG_BFRAME;

	if (flags & VIRTIO_VIDEO_BUFFER_PFRAME)
		v4l2_vb->flags |= V4L2_BUF_FLAG_PFRAME;

	if (flags & VIRTIO_VIDEO_BUFFER_F_EOS) {
		v4l2_vb->flags |= V4L2_BUF_FLAG_LAST;
		ret = virtio_video_req_stream_stop(vv, vvd->id, stream);
		if (ret)
			v4l2_err(&vv->v4l2_dev, "failed to stop stream\n");
		else
			stream->state = STREAM_STATE_STOPPED;
		virtio_video_queue_eos_event(stream);
	}

	if (!V4L2_TYPE_IS_OUTPUT(vb2_queue->type)) {
		if (vvd->type == VIRTIO_VIDEO_FUNC_ENCODER) {
			vb->planes[0].bytesused = size;
		} else if (vvd->type == VIRTIO_VIDEO_FUNC_DECODER) {
			p_info = &stream->out_info;
			for (i = 0; i < p_info->num_planes; i++)
				vb->planes[i].bytesused =
					p_info->plane_format[i].plane_size;
		}

		vb->timestamp = timestamp;
	}

	v4l2_m2m_buf_done(v4l2_vb, done_state);
}


static void virtio_video_worker(struct work_struct *work)
{
	unsigned int i;
	int ret;
	struct vb2_buffer *vb2_buf;
	struct vb2_v4l2_buffer *src_vb, *dst_vb;
	struct virtio_video_buffer *virtio_vb;
	struct virtio_video_stream *stream = work2stream(work);
	struct virtio_video_device *vvd = to_virtio_vd(stream->video_dev);
	struct vb2_queue *src_vq =
		v4l2_m2m_get_vq(stream->fh.m2m_ctx,
				V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE);
	struct vb2_queue *dst_vq =
		v4l2_m2m_get_vq(stream->fh.m2m_ctx,
				V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE);
	struct virtio_video *vv = vvd->vv;
	uint32_t data_size[VB2_MAX_PLANES] = {0};


	mutex_lock(dst_vq->lock);
	for (;;) {
		dst_vb = v4l2_m2m_next_dst_buf(stream->fh.m2m_ctx);
		if (dst_vb == NULL)
			break;

		vb2_buf = &dst_vb->vb2_buf;
		virtio_vb = to_virtio_vb(vb2_buf);

		for (i = 0; i < vb2_buf->num_planes; ++i)
			data_size[i] = vb2_buf->planes[i].bytesused;

		ret = virtio_video_req_resource_queue(vv, vvd->id,
						      stream->stream_id,
						      virtio_vb, data_size,
						      vb2_buf->num_planes,
						      false);
		if (ret) {
			v4l2_info(&vv->v4l2_dev,
				  "failed to queue a dst buffer\n");
			v4l2_m2m_job_finish(vvd->m2m_dev, stream->fh.m2m_ctx);
			mutex_unlock(dst_vq->lock);
			return;
		}

		virtio_vb->queued = true;
		stream->dst_cleared = false;
		dst_vb = v4l2_m2m_dst_buf_remove(stream->fh.m2m_ctx);
	}
	mutex_unlock(dst_vq->lock);

	mutex_lock(src_vq->lock);
	for (;;) {
		if (stream->state == STREAM_STATE_DRAIN)
			break;

		src_vb = v4l2_m2m_next_src_buf(stream->fh.m2m_ctx);
		if (src_vb == NULL)
			break;

		vb2_buf = &src_vb->vb2_buf;
		virtio_vb = to_virtio_vb(vb2_buf);

		for (i = 0; i < vb2_buf->num_planes; ++i)
			data_size[i] = vb2_buf->planes[i].bytesused;

		ret = virtio_video_req_resource_queue(vv, vvd->id,
						      stream->stream_id,
						      virtio_vb,
							  data_size,
							  vb2_buf->num_planes,
						      true);
		if (ret) {
			v4l2_info(&vv->v4l2_dev,
				  "failed to queue an src buffer\n");
			v4l2_m2m_job_finish(vvd->m2m_dev, stream->fh.m2m_ctx);
			mutex_unlock(src_vq->lock);
			return;
		}

		virtio_vb->queued = true;
		stream->src_cleared = false;
		src_vb = v4l2_m2m_src_buf_remove(stream->fh.m2m_ctx);
	}
	mutex_unlock(src_vq->lock);

	v4l2_m2m_job_finish(vvd->m2m_dev, stream->fh.m2m_ctx);
}

static int virtio_video_device_open(struct file *file)
{
	int ret;
	uint32_t stream_id;
	char name[TASK_COMM_LEN];
	struct virtio_video_stream *stream;
	struct video_device *video_dev = video_devdata(file);
	struct virtio_video_device *vvd = video_drvdata(file);
	struct virtio_video *vv = vvd->vv;

	stream = kzalloc(sizeof(*stream), GFP_KERNEL);
	if (!stream)
		return -ENOMEM;

	get_task_comm(name, current);
	virtio_video_stream_id_get(vv, stream, &stream_id);
	ret = virtio_video_req_stream_create(vv, vvd->id, stream_id, name);
	if (ret) {
		v4l2_err(&vv->v4l2_dev, "failed to create stream\n");
		goto err_stream_create;
	}

	stream->video_dev = video_dev;
	stream->stream_id = stream_id;
	stream->state = STREAM_STATE_IDLE;
	mutex_init(&stream->vq_mutex);
	INIT_WORK(&stream->work, virtio_video_worker);
	v4l2_fh_init(&stream->fh, video_dev);
	stream->fh.ctrl_handler = &stream->ctrl_handler;

	if (vvd->type == VIRTIO_VIDEO_FUNC_DECODER) {
		stream->fh.m2m_ctx =
			v4l2_m2m_ctx_init(vvd->m2m_dev, stream,
					  &virtio_video_init_dec_queues);
	} else if (vvd->type == VIRTIO_VIDEO_FUNC_ENCODER) {
		stream->fh.m2m_ctx =
			v4l2_m2m_ctx_init(vvd->m2m_dev, stream,
					  &virtio_video_init_enc_queues);
	} else {
		v4l2_err(&vv->v4l2_dev, "unsupported device type\n");
		goto err_stream_create;
	}

	v4l2_m2m_set_src_buffered(stream->fh.m2m_ctx, true);
	v4l2_m2m_set_dst_buffered(stream->fh.m2m_ctx, true);
	file->private_data = &stream->fh;
	v4l2_fh_add(&stream->fh);

	if (vvd->type == VIRTIO_VIDEO_FUNC_DECODER)
		ret = virtio_video_init_dec_ctrls(stream);
	else if (vvd->type == VIRTIO_VIDEO_FUNC_ENCODER)
		ret = virtio_video_init_enc_ctrls(stream);

	if (ret) {
		v4l2_err(&vv->v4l2_dev, "failed to init controls\n");
		goto err_init_ctrls;
	}

	ret = virtio_video_req_get_params(vv, vvd->id, VIDEO_PIN_TYPE_INPUT,
					  VIDEO_PARAMS_SCOPE_STREAM, stream);
	if (ret) {
		v4l2_err(&vv->v4l2_dev, "failed to get stream in params\n");
		goto err_init_ctrls;
	}

	ret = virtio_video_req_get_params(vv, vvd->id, VIDEO_PIN_TYPE_OUTPUT,
					  VIDEO_PARAMS_SCOPE_STREAM, stream);
	if (ret) {
		v4l2_err(&vv->v4l2_dev, "failed to get stream out params\n");
		goto err_init_ctrls;
	}

	return 0;

err_init_ctrls:
	v4l2_fh_del(&stream->fh);
	v4l2_fh_exit(&stream->fh);
	mutex_lock(video_dev->lock);
	v4l2_m2m_ctx_release(stream->fh.m2m_ctx);
	mutex_unlock(video_dev->lock);
err_stream_create:
	virtio_video_stream_id_put(vv, stream_id);
	kfree(stream);

	return ret;
}

static int virtio_video_device_release(struct file *file)
{
	struct virtio_video_stream *stream = file2stream(file);
	struct video_device *video_dev = video_devdata(file);
	struct virtio_video_device *vvd = video_drvdata(file);
	struct virtio_video *vv = vvd->vv;

	v4l2_fh_del(&stream->fh);
	v4l2_fh_exit(&stream->fh);
	mutex_lock(video_dev->lock);
	v4l2_m2m_ctx_release(stream->fh.m2m_ctx);
	mutex_unlock(video_dev->lock);

	virtio_video_req_stream_destroy(vv, vvd->id, stream->stream_id);
	virtio_video_stream_id_put(vv, stream->stream_id);

	kfree(stream);

	return 0;
}

static const struct v4l2_file_operations virtio_video_device_fops = {
	.owner		= THIS_MODULE,
	.open		= virtio_video_device_open,
	.release	= virtio_video_device_release,
	.poll		= v4l2_m2m_fop_poll,
	.unlocked_ioctl	= video_ioctl2,
	.mmap		= v4l2_m2m_fop_mmap,
};

static void virtio_video_device_run(void *priv)
{
	struct virtio_video_stream *stream = priv;
	struct virtio_video_device *vvd = to_virtio_vd(stream->video_dev);

	queue_work(vvd->workqueue, &stream->work);
}

static int virtio_video_device_job_ready(void *priv)
{
	struct virtio_video_stream *stream = priv;

	if (stream->state == STREAM_STATE_STOPPED)
		return 0;

	if (v4l2_m2m_num_src_bufs_ready(stream->fh.m2m_ctx) > 0 ||
	    v4l2_m2m_num_dst_bufs_ready(stream->fh.m2m_ctx) > 0)
		return 1;

	return 0;
}

static void virtio_video_device_job_abort(void *priv)
{
	struct virtio_video_stream *stream = priv;
	struct virtio_video_device *vvd = to_virtio_vd(stream->video_dev);

	v4l2_m2m_job_finish(vvd->m2m_dev, stream->fh.m2m_ctx);
}

static const struct v4l2_m2m_ops virtio_video_device_m2m_ops = {
	.device_run	= virtio_video_device_run,
	.job_ready	= virtio_video_device_job_ready,
	.job_abort	= virtio_video_device_job_abort,
};

uint32_t virtio_video_control_to_v4l2(uint32_t control_type)
{
	switch (control_type) {
	case VIRTIO_VIDEO_CONTROL_BITRATE:
		return V4L2_CID_MPEG_VIDEO_BITRATE;
	case VIRTIO_VIDEO_CONTROL_PROFILE:
		return V4L2_CID_MPEG_VIDEO_H264_PROFILE;
	case VIRTIO_VIDEO_CONTROL_LEVEL:
		return V4L2_CID_MPEG_VIDEO_H264_LEVEL;
	default:
		return 0;
	}
}

uint32_t virtio_video_profile_to_v4l2(uint32_t profile)
{
	switch (profile) {
	case VIRTIO_MPEG_VIDEO_H264_PROFILE_BASELINE:
		return V4L2_MPEG_VIDEO_H264_PROFILE_BASELINE;
	case VIRTIO_MPEG_VIDEO_H264_PROFILE_CONSTRAINED_BASELINE:
		return V4L2_MPEG_VIDEO_H264_PROFILE_CONSTRAINED_BASELINE;
	case VIRTIO_MPEG_VIDEO_H264_PROFILE_MAIN:
		return V4L2_MPEG_VIDEO_H264_PROFILE_MAIN;
	case VIRTIO_MPEG_VIDEO_H264_PROFILE_EXTENDED:
		return V4L2_MPEG_VIDEO_H264_PROFILE_EXTENDED;
	case VIRTIO_MPEG_VIDEO_H264_PROFILE_HIGH:
		return V4L2_MPEG_VIDEO_H264_PROFILE_HIGH;
	case VIRTIO_MPEG_VIDEO_H264_PROFILE_HIGH_10:
		return V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_10;
	case VIRTIO_MPEG_VIDEO_H264_PROFILE_HIGH_422:
		return V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_422;
	case VIRTIO_MPEG_VIDEO_H264_PROFILE_HIGH_444_PREDICTIVE:
		return V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_444_PREDICTIVE;
	case VIRTIO_MPEG_VIDEO_H264_PROFILE_HIGH_10_INTRA:
		return V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_10_INTRA;
	case VIRTIO_MPEG_VIDEO_H264_PROFILE_HIGH_422_INTRA:
		return V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_422_INTRA;
	case VIRTIO_MPEG_VIDEO_H264_PROFILE_HIGH_444_INTRA:
		return V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_444_INTRA;
	case VIRTIO_MPEG_VIDEO_H264_PROFILE_CAVLC_444_INTRA:
		return V4L2_MPEG_VIDEO_H264_PROFILE_CAVLC_444_INTRA;
	case VIRTIO_MPEG_VIDEO_H264_PROFILE_SCALABLE_BASELINE:
		return V4L2_MPEG_VIDEO_H264_PROFILE_SCALABLE_BASELINE;
	case VIRTIO_MPEG_VIDEO_H264_PROFILE_SCALABLE_HIGH:
		return V4L2_MPEG_VIDEO_H264_PROFILE_SCALABLE_HIGH;
	case VIRTIO_MPEG_VIDEO_H264_PROFILE_SCALABLE_HIGH_INTRA:
		return V4L2_MPEG_VIDEO_H264_PROFILE_SCALABLE_HIGH_INTRA;
	case VIRTIO_MPEG_VIDEO_H264_PROFILE_STEREO_HIGH:
		return V4L2_MPEG_VIDEO_H264_PROFILE_STEREO_HIGH;
	case VIRTIO_MPEG_VIDEO_H264_PROFILE_MULTIVIEW_HIGH:
		return V4L2_MPEG_VIDEO_H264_PROFILE_MULTIVIEW_HIGH;
	default:
		return 0;
	}
}

uint32_t virtio_video_level_to_v4l2(uint32_t level)
{
	switch (level) {
	case VIRTIO_MPEG_VIDEO_H264_LEVEL_1_0:
		return V4L2_MPEG_VIDEO_H264_LEVEL_1_0;
	case VIRTIO_MPEG_VIDEO_H264_LEVEL_2_0:
		return V4L2_MPEG_VIDEO_H264_LEVEL_2_0;
	case VIRTIO_MPEG_VIDEO_H264_LEVEL_4_0:
		return V4L2_MPEG_VIDEO_H264_LEVEL_4_0;
	case VIRTIO_MPEG_VIDEO_H264_LEVEL_4_1:
		return V4L2_MPEG_VIDEO_H264_LEVEL_4_1;
	case VIRTIO_MPEG_VIDEO_H264_LEVEL_4_2:
		return V4L2_MPEG_VIDEO_H264_LEVEL_4_2;
	case VIRTIO_MPEG_VIDEO_H264_LEVEL_5_0:
		return V4L2_MPEG_VIDEO_H264_LEVEL_5_0;
	case VIRTIO_MPEG_VIDEO_H264_LEVEL_5_1:
		return V4L2_MPEG_VIDEO_H264_LEVEL_5_1;
	default:
		return 0;
	}
}

uint32_t virtio_video_v4l2_control_to_virtio(uint32_t v4l2_control)
{
	switch (v4l2_control) {
	case V4L2_CID_MPEG_VIDEO_BITRATE:
		return VIRTIO_VIDEO_CONTROL_BITRATE;
	case V4L2_CID_MPEG_VIDEO_H264_PROFILE:
		return VIRTIO_VIDEO_CONTROL_PROFILE;
	case V4L2_CID_MPEG_VIDEO_H264_LEVEL:
		return VIRTIO_VIDEO_CONTROL_LEVEL;
	default:
		return 0;
	}
}

uint32_t virtio_video_v4l2_profile_to_virtio(uint32_t v4l2_profile)
{
	switch (v4l2_profile) {
	case V4L2_MPEG_VIDEO_H264_PROFILE_BASELINE:
		return VIRTIO_MPEG_VIDEO_H264_PROFILE_BASELINE;
	case V4L2_MPEG_VIDEO_H264_PROFILE_MAIN:
		return VIRTIO_MPEG_VIDEO_H264_PROFILE_MAIN;
	case V4L2_MPEG_VIDEO_H264_PROFILE_EXTENDED:
		return VIRTIO_MPEG_VIDEO_H264_PROFILE_EXTENDED;
	case V4L2_MPEG_VIDEO_H264_PROFILE_HIGH:
		return VIRTIO_MPEG_VIDEO_H264_PROFILE_HIGH;
	case V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_10:
		return VIRTIO_MPEG_VIDEO_H264_PROFILE_HIGH_10;
	case V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_422:
		return VIRTIO_MPEG_VIDEO_H264_PROFILE_HIGH_422;
	case V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_444_PREDICTIVE:
		return VIRTIO_MPEG_VIDEO_H264_PROFILE_HIGH_444_PREDICTIVE;
	case V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_10_INTRA:
		return VIRTIO_MPEG_VIDEO_H264_PROFILE_HIGH_10_INTRA;
	case V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_422_INTRA:
		return VIRTIO_MPEG_VIDEO_H264_PROFILE_HIGH_422_INTRA;
	case V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_444_INTRA:
		return VIRTIO_MPEG_VIDEO_H264_PROFILE_HIGH_444_INTRA;
	case V4L2_MPEG_VIDEO_H264_PROFILE_CAVLC_444_INTRA:
		return VIRTIO_MPEG_VIDEO_H264_PROFILE_CAVLC_444_INTRA;
	case V4L2_MPEG_VIDEO_H264_PROFILE_SCALABLE_BASELINE:
		return VIRTIO_MPEG_VIDEO_H264_PROFILE_SCALABLE_BASELINE;
	case V4L2_MPEG_VIDEO_H264_PROFILE_SCALABLE_HIGH:
		return VIRTIO_MPEG_VIDEO_H264_PROFILE_SCALABLE_HIGH;
	case V4L2_MPEG_VIDEO_H264_PROFILE_SCALABLE_HIGH_INTRA:
		return VIRTIO_MPEG_VIDEO_H264_PROFILE_SCALABLE_HIGH_INTRA;
	case V4L2_MPEG_VIDEO_H264_PROFILE_STEREO_HIGH:
		return VIRTIO_MPEG_VIDEO_H264_PROFILE_STEREO_HIGH;
	case V4L2_MPEG_VIDEO_H264_PROFILE_MULTIVIEW_HIGH:
		return VIRTIO_MPEG_VIDEO_H264_PROFILE_MULTIVIEW_HIGH;
	default:
		return VIRTIO_MPEG_VIDEO_H264_PROFILE_UNDEFINED;
	}
}

uint32_t virtio_video_v4l2_level_to_virtio(uint32_t v4l2_level)
{
	switch (v4l2_level) {
	case V4L2_MPEG_VIDEO_H264_LEVEL_1_0:
		return VIRTIO_MPEG_VIDEO_H264_LEVEL_1_0;
	case V4L2_MPEG_VIDEO_H264_LEVEL_2_0:
		return VIRTIO_MPEG_VIDEO_H264_LEVEL_2_0;
	case V4L2_MPEG_VIDEO_H264_LEVEL_4_0:
		return VIRTIO_MPEG_VIDEO_H264_LEVEL_4_0;
	case V4L2_MPEG_VIDEO_H264_LEVEL_4_1:
		return VIRTIO_MPEG_VIDEO_H264_LEVEL_4_1;
	case V4L2_MPEG_VIDEO_H264_LEVEL_4_2:
		return VIRTIO_MPEG_VIDEO_H264_LEVEL_4_2;
	case V4L2_MPEG_VIDEO_H264_LEVEL_5_0:
		return VIRTIO_MPEG_VIDEO_H264_LEVEL_5_0;
	case V4L2_MPEG_VIDEO_H264_LEVEL_5_1:
		return VIRTIO_MPEG_VIDEO_H264_LEVEL_5_1;
	default:
		return VIRTIO_MPEG_VIDEO_H264_LEVEL_UNDEFINED;
	}
}

uint32_t virtio_video_format_to_v4l2(uint32_t pixel_format)
{

	switch (pixel_format) {
	case VIRTIO_VIDEO_PIX_FMT_H264:
		return V4L2_PIX_FMT_H264;
	case VIRTIO_VIDEO_PIX_FMT_H265:
		return V4L2_PIX_FMT_HEVC;
	case VIRTIO_VIDEO_PIX_FMT_MPEG4:
		return V4L2_PIX_FMT_MPEG4;
	case VIRTIO_VIDEO_PIX_FMT_MPEG2:
		return V4L2_PIX_FMT_MPEG2;
	case VIRTIO_VIDEO_PIX_FMT_NV12:
		return V4L2_PIX_FMT_NV12;
	case VIRTIO_VIDEO_PIX_FMT_I420:
		return V4L2_PIX_FMT_YUV420;
	default:
		return 0;
	}
}

uint32_t virtio_video_v4l2_fourcc_to_virtio(uint32_t fourcc)
{
	switch (fourcc) {
	case V4L2_PIX_FMT_H264:
		return VIRTIO_VIDEO_PIX_FMT_H264;
	case V4L2_PIX_FMT_HEVC:
		return VIRTIO_VIDEO_PIX_FMT_H265;
	case V4L2_PIX_FMT_MPEG4:
		return VIRTIO_VIDEO_PIX_FMT_MPEG4;
	case V4L2_PIX_FMT_MPEG2:
		return VIRTIO_VIDEO_PIX_FMT_MPEG2;
	case V4L2_PIX_FMT_NV12:
		return VIRTIO_VIDEO_PIX_FMT_NV12;
	case V4L2_PIX_FMT_YUV420:
		return VIRTIO_VIDEO_PIX_FMT_I420;
	default:
		return VIRTIO_VIDEO_PIX_FMT_UNKNOWN;
	}
}

static int virtio_video_device_init(struct virtio_video_device *vvd)
{
	int ret = 0;
	const char *device_name = NULL;
	struct video_device *vd = NULL;
	struct virtio_video *vv = NULL;

	if (!vvd)
		return -EINVAL;

	vd = &vvd->video_dev;
	vv = vvd->vv;

	switch (vvd->type) {
	case VIRTIO_VIDEO_FUNC_ENCODER:
		device_name = "stateful-encoder";
		ret = virtio_video_enc_init(vvd);
		break;
	case VIRTIO_VIDEO_FUNC_DECODER:
		device_name = "stateful-decoder";
		ret = virtio_video_dec_init(vvd);
		break;
	case VIRTIO_VIDEO_FUNC_PROCESSOR:
	case VIRTIO_VIDEO_FUNC_CAPTURE:
	case VIRTIO_VIDEO_FUNC_OUTPUT:
	default:
		ret = -EINVAL;
		break;
	}

	if (ret) {
		v4l2_err(&vv->v4l2_dev, "failed to init device type");
		return ret;
	}

	ret = video_register_device(vd, VFL_TYPE_GRABBER, 0);
	if (ret) {
		v4l2_err(&vv->v4l2_dev, "failed to register video device\n");
		return ret;
	}

	vvd->workqueue = alloc_ordered_workqueue(vd->name,
						 WQ_MEM_RECLAIM | WQ_FREEZABLE);
	if (!vvd->workqueue) {
		v4l2_err(&vv->v4l2_dev, "failed to create a workqueue");
		video_unregister_device(vd);
		return -ENOMEM;
	}

	list_add(&vvd->devices_list_entry, &vv->devices_list);
	v4l2_info(&vv->v4l2_dev, "Device '%s' registered as /dev/video%d\n",
		  device_name, vd->num);

	return 0;
}

static void virtio_video_device_deinit(struct virtio_video_device *vvd)
{
	if (!vvd)
		return;

	list_del(&vvd->devices_list_entry);
	flush_workqueue(vvd->workqueue);
	destroy_workqueue(vvd->workqueue);
	video_unregister_device(&vvd->video_dev);
}

static struct virtio_video_device *
virtio_video_device_create(struct virtio_video *vv)
{
	struct device *dev = NULL;
	struct video_device *vd = NULL;
	struct v4l2_m2m_dev *m2m_dev = NULL;
	struct virtio_video_device *vvd = NULL;

	if (!vv)
		return ERR_PTR(-EINVAL);

	dev = &vv->vdev->dev;

	vvd = devm_kzalloc(dev, sizeof(*vvd), GFP_KERNEL);
	if (!vvd)
		return ERR_PTR(-ENOMEM);

	m2m_dev = v4l2_m2m_init(&virtio_video_device_m2m_ops);
	if (IS_ERR(m2m_dev)) {
		v4l2_err(&vv->v4l2_dev, "failed to init m2m device\n");
		goto err;
	}

	vvd->vv = vv;
	vvd->m2m_dev = m2m_dev;
	mutex_init(&vvd->video_dev_mutex);
	vd = &vvd->video_dev;
	vd->lock = &vvd->video_dev_mutex;
	vd->v4l2_dev = &vv->v4l2_dev;
	vd->vfl_dir = VFL_DIR_M2M;
	vd->ioctl_ops = NULL;
	vd->fops = &virtio_video_device_fops;
	vd->device_caps = V4L2_CAP_STREAMING | V4L2_CAP_VIDEO_M2M_MPLANE;
	vd->release = video_device_release_empty;

	memset(vd->name, 0, sizeof(vd->name));

	video_set_drvdata(vd, vvd);

	INIT_LIST_HEAD(&vvd->ctrl_caps_list);
	INIT_LIST_HEAD(&vvd->fmt_caps_list);

	vvd->num_output_formats = 0;
	vvd->num_capture_formats = 0;

	return vvd;

err:
	devm_kfree(dev, vvd);

	return ERR_CAST(m2m_dev);
}

void virtio_video_device_destroy(struct virtio_video_device *vvd)
{
	if (!vvd)
		return;

	v4l2_m2m_release(vvd->m2m_dev);
	devm_kfree(&vvd->vv->vdev->dev, vvd);
}

int virtio_video_devices_init(struct virtio_video *vv, void *funcs_buf)
{
	int ret = 0;
	int fun_idx = 0;
	size_t offset = 0;

	if (!vv || !funcs_buf)
		return -EINVAL;

	for (fun_idx = 0; fun_idx < vv->num_devices; fun_idx++) {
		struct virtio_video_device *vvd = NULL;
		size_t func_size = 0;

		vvd = virtio_video_device_create(vv);
		if (IS_ERR(vvd)) {
			v4l2_err(&vv->v4l2_dev,
				 "failed to create virtio video device\n");
			ret = PTR_ERR(vvd);
			goto failed;
		}

		func_size = virtio_video_parse_virtio_function(funcs_buf +
							       offset, vvd);
		if (func_size == 0) {
			v4l2_err(&vv->v4l2_dev, "failed to parse a function\n");
			virtio_video_device_destroy(vvd);
			ret = -EINVAL;
			goto failed;
		}
		offset += func_size;

		ret = virtio_video_device_init(vvd);
		if (ret != 0) {
			v4l2_err(&vv->v4l2_dev,
				 "failed to init virtio video device\n");
			virtio_video_clean_virtio_function(vvd);
			virtio_video_device_destroy(vvd);
			goto failed;
		}
	}

	return 0;

failed:
	virtio_video_devices_deinit(vv);

	return ret;
}

void virtio_video_devices_deinit(struct virtio_video *vv)
{
	struct virtio_video_device *vvd = NULL, *tmp = NULL;

	list_for_each_entry_safe(vvd, tmp, &vv->devices_list,
				 devices_list_entry) {
		virtio_video_device_deinit(vvd);
		virtio_video_clean_virtio_function(vvd);
		virtio_video_device_destroy(vvd);
	}
}
