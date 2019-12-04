// SPDX-License-Identifier: GPL-2.0+
/* Decoder for virtio video device.
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

static int virtio_video_queue_setup(struct vb2_queue *vq,
				    unsigned int *num_buffers,
				    unsigned int *num_planes,
				    unsigned int sizes[],
				    struct device *alloc_devs[])
{
	int i;
	struct virtio_video_stream *stream = vb2_get_drv_priv(vq);
	struct video_format_info *p_info;

	if (*num_planes)
		return 0;

	if (V4L2_TYPE_IS_OUTPUT(vq->type))
		p_info = &stream->in_info;
	else
		p_info = &stream->out_info;

	*num_planes = p_info->num_planes;

	for (i = 0; i < p_info->num_planes; i++)
		sizes[i] = p_info->plane_format[i].plane_size;

	return 0;
}

static int virtio_video_buf_plane_init(uint32_t idx,
				       uint32_t resource_id,
				       struct virtio_video_device *vvd,
				       struct virtio_video_stream *stream,
				       struct vb2_buffer *vb)
{
	int ret;
	unsigned int i;
	struct virtio_video *vv = vvd->vv;
	struct scatterlist *sg;
	struct virtio_video_mem_entry *ents;
	struct sg_table *sgt = vb2_dma_sg_plane_desc(vb, idx);

	/* Freed when the request has been completed */
	ents = kcalloc(sgt->nents, sizeof(*ents), GFP_KERNEL);
	for_each_sg(sgt->sgl, sg, sgt->nents, i) {
		ents[i].addr = cpu_to_le64(vv->has_iommu
					   ? sg_dma_address(sg)
					   : sg_phys(sg));
		ents[i].length = cpu_to_le32(sg->length);
	}

	v4l2_dbg(1, vv->debug, &vv->v4l2_dev, "mem entries:\n");
	if (vv->debug >= 1) {
		for (i = 0; i < sgt->nents; i++)
			pr_debug("\t%03i: addr=%llx length=%u\n", i,
				 ents[i].addr, ents[i].length);
	}

	ret = virtio_video_req_resource_attach_backing(vv, vvd->id,
						       stream->stream_id,
						       resource_id, ents,
						       sgt->nents);
	if (ret)
		kfree(ents);

	return ret;
}

static int virtio_video_buf_init(struct vb2_buffer *vb)
{
	int ret = 0;
	unsigned int i;
	uint32_t resource_id;
	struct virtio_video_stream *stream = vb2_get_drv_priv(vb->vb2_queue);
	struct virtio_video_buffer *virtio_vb = to_virtio_vb(vb);
	struct virtio_video_device *vvd = to_virtio_vd(stream->video_dev);
	struct virtio_video *vv = vvd->vv;

	virtio_video_resource_id_get(vv, &resource_id);
	ret = virtio_video_req_resource_create(vv, vvd->id, stream->stream_id,
					       resource_id);
	if (ret)
		return ret;

	for (i = 0; i < vb->num_planes; ++i) {
		ret = virtio_video_buf_plane_init(i,
				resource_id, vvd, stream, vb);
		if (ret)
			break;
	}

	if (ret) {
		virtio_video_req_resource_destroy(vvd->vv, vvd->id,
						  stream->stream_id,
						  resource_id);
		virtio_video_resource_id_put(vvd->vv, resource_id);
		return ret;
	}

	virtio_vb->queued = false;
	virtio_vb->detached = false;
	virtio_vb->resource_id = resource_id;

	return 0;
}

static void virtio_video_buf_cleanup(struct vb2_buffer *vb)
{
	int ret;
	struct virtio_video_stream *stream = vb2_get_drv_priv(vb->vb2_queue);
	struct virtio_video_buffer *virtio_vb = to_virtio_vb(vb);
	struct virtio_video_device *vvd = to_virtio_vd(stream->video_dev);
	struct virtio_video *vv = vvd->vv;

	ret = virtio_video_req_resource_detach_backing(vv, vvd->id,
						       stream->stream_id,
						       virtio_vb);
	if (ret)
		return;

	ret = wait_event_timeout(vv->wq, virtio_vb->detached, 5 * HZ);
	if (ret == 0) {
		v4l2_err(&vv->v4l2_dev, "timed out waiting for detach\n");
		return;
	}

	virtio_video_req_resource_destroy(vv, vvd->id, stream->stream_id,
					  virtio_vb->resource_id);
	virtio_video_resource_id_put(vv, virtio_vb->resource_id);
}

static void virtio_video_buf_queue(struct vb2_buffer *vb)
{
	int i, ret;
	struct vb2_buffer *src_buf;
	struct virtio_video_buffer *virtio_vb;
	uint32_t data_size[VB2_MAX_PLANES] = {0};
	struct vb2_v4l2_buffer *v4l2_vb = to_vb2_v4l2_buffer(vb);
	struct vb2_v4l2_buffer *src_vb;
	struct virtio_video_stream *stream = vb2_get_drv_priv(vb->vb2_queue);
	struct virtio_video_device *vvd = to_virtio_vd(stream->video_dev);
	struct virtio_video *vv = vvd->vv;

	v4l2_m2m_buf_queue(stream->fh.m2m_ctx, v4l2_vb);

	if ((stream->state != STREAM_STATE_INIT) ||
	    !V4L2_TYPE_IS_OUTPUT(vb->vb2_queue->type))
		return;

	src_vb = v4l2_m2m_next_src_buf(stream->fh.m2m_ctx);
	if (!src_vb) {
		v4l2_err(&vv->v4l2_dev, "no src buf during initialization\n");
		return;
	}

	src_buf = &src_vb->vb2_buf;
	for (i = 0; i < src_buf->num_planes; ++i)
		data_size[i] = src_buf->planes[i].bytesused;

	virtio_vb = to_virtio_vb(src_buf);

	ret = virtio_video_req_resource_queue(vv, vvd->id, stream->stream_id,
					      virtio_vb, data_size,
					      src_buf->num_planes,
					      true);
	if (ret) {
		v4l2_err(&vv->v4l2_dev, "failed to queue an src buffer\n");
		return;
	}

	virtio_vb->queued = true;
	stream->src_cleared = false;
	src_vb = v4l2_m2m_src_buf_remove(stream->fh.m2m_ctx);
}

static int virtio_video_start_streaming(struct vb2_queue *vq,
					unsigned int count)
{
	int ret;
	struct virtio_video_stream *stream = vb2_get_drv_priv(vq);
	struct virtio_video_device *vvd = to_virtio_vd(stream->video_dev);
	struct virtio_video *vv = vvd->vv;

	if ((V4L2_TYPE_IS_OUTPUT(vq->type) &&
	    (stream->state == STREAM_STATE_INIT)) ||
	    (stream->state == STREAM_STATE_STOPPED)) {
		ret = virtio_video_req_stream_start(vv, vvd->id,
						    stream->stream_id);
		if (ret)
			return ret;
	}

	if (!V4L2_TYPE_IS_OUTPUT(vq->type) &&
	    (stream->state >= STREAM_STATE_INIT))
		stream->state = STREAM_STATE_RUNNING;

	return 0;
}

static void virtio_video_stop_streaming(struct vb2_queue *vq)
{
	int ret;
	bool *cleared;
	bool is_output = V4L2_TYPE_IS_OUTPUT(vq->type);
	struct virtio_video_stream *stream = vb2_get_drv_priv(vq);
	struct virtio_video_device *vvd = to_virtio_vd(stream->video_dev);
	struct virtio_video *vv = vvd->vv;
	struct vb2_v4l2_buffer *v4l2_vb;

	if (is_output)
		cleared = &stream->src_cleared;
	else
		cleared = &stream->dst_cleared;

	ret = virtio_video_req_queue_clear(vv, vvd->id, stream, is_output);
	if (ret) {
		v4l2_err(&vv->v4l2_dev, "failed to clear queue\n");
		return;
	}

	ret = wait_event_timeout(vv->wq, *cleared, 5 * HZ);
	if (ret == 0) {
		v4l2_err(&vv->v4l2_dev, "timed out waiting for queue clear\n");
		return;
	}

	for (;;) {
		if (is_output)
			v4l2_vb = v4l2_m2m_src_buf_remove(stream->fh.m2m_ctx);
		else
			v4l2_vb = v4l2_m2m_dst_buf_remove(stream->fh.m2m_ctx);
		if (!v4l2_vb)
			break;
		v4l2_m2m_buf_done(v4l2_vb, VB2_BUF_STATE_ERROR);
	}
}

static const struct vb2_ops virtio_video_qops = {
	.queue_setup	 = virtio_video_queue_setup,
	.buf_init	 = virtio_video_buf_init,
	.buf_cleanup	 = virtio_video_buf_cleanup,
	.buf_queue	 = virtio_video_buf_queue,
	.start_streaming = virtio_video_start_streaming,
	.stop_streaming  = virtio_video_stop_streaming,
	.wait_prepare	 = vb2_ops_wait_prepare,
	.wait_finish	 = vb2_ops_wait_finish,
};

static int virtio_video_g_volatile_ctrl(struct v4l2_ctrl *ctrl)
{
	int ret = 0;
	struct virtio_video_stream *stream = ctrl2stream(ctrl);
	struct virtio_video_device *vvd = to_virtio_vd(stream->video_dev);

	switch (ctrl->id) {
	case V4L2_CID_MIN_BUFFERS_FOR_CAPTURE:
		if (stream->state >= STREAM_STATE_METADATA)
			ctrl->val = vvd->out_info.min_buffers;
		else
			ctrl->val = 0;
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

static const struct v4l2_ctrl_ops virtio_video_ctrl_ops = {
	.g_volatile_ctrl	= virtio_video_g_volatile_ctrl,
};

int virtio_video_init_dec_ctrls(struct virtio_video_stream *stream)
{
	struct v4l2_ctrl *ctrl;

	v4l2_ctrl_handler_init(&stream->ctrl_handler, 1);

	ctrl = v4l2_ctrl_new_std(&stream->ctrl_handler,
				&virtio_video_ctrl_ops,
				V4L2_CID_MIN_BUFFERS_FOR_CAPTURE,
				MIN_BUFS_MIN, MIN_BUFS_MAX, MIN_BUFS_STEP,
				MIN_BUFS_DEF);
	ctrl->flags |= V4L2_CTRL_FLAG_VOLATILE;

	if (stream->ctrl_handler.error)
		return stream->ctrl_handler.error;

	v4l2_ctrl_handler_setup(&stream->ctrl_handler);

	return 0;
}

int virtio_video_init_dec_queues(void *priv, struct vb2_queue *src_vq,
				 struct vb2_queue *dst_vq)
{
	int ret;
	struct virtio_video_stream *stream = priv;
	struct virtio_video_device *vvd = to_virtio_vd(stream->video_dev);
	struct device *dev = vvd->vv->v4l2_dev.dev;

	src_vq->type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	src_vq->io_modes = VB2_MMAP | VB2_DMABUF;
	src_vq->drv_priv = stream;
	src_vq->buf_struct_size = sizeof(struct virtio_video_buffer);
	src_vq->ops = &virtio_video_qops;
	src_vq->mem_ops = &vb2_dma_sg_memops;
	src_vq->min_buffers_needed = vvd->in_info.min_buffers;
	src_vq->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;
	src_vq->lock = &stream->vq_mutex;
	src_vq->dev = dev;

	ret = vb2_queue_init(src_vq);
	if (ret)
		return ret;

	dst_vq->type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	dst_vq->io_modes = VB2_MMAP | VB2_DMABUF;
	dst_vq->drv_priv = stream;
	dst_vq->buf_struct_size = sizeof(struct virtio_video_buffer);
	dst_vq->ops = &virtio_video_qops;
	dst_vq->mem_ops = &vb2_dma_sg_memops;
	dst_vq->min_buffers_needed = vvd->out_info.min_buffers;
	dst_vq->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_COPY;
	dst_vq->lock = &stream->vq_mutex;
	dst_vq->dev = dev;

	return vb2_queue_init(dst_vq);
}

static int virtio_video_querycap(struct file *file, void *fh,
				 struct v4l2_capability *cap)
{
	struct video_device *video_dev = video_devdata(file);

	strncpy(cap->driver, DRIVER_NAME, sizeof(cap->driver));
	strncpy(cap->card, video_dev->name, sizeof(cap->card));
	snprintf(cap->bus_info, sizeof(cap->bus_info), "virtio:%s",
		 video_dev->name);

	cap->device_caps = V4L2_CAP_VIDEO_M2M_MPLANE | V4L2_CAP_STREAMING;
	cap->capabilities = cap->device_caps | V4L2_CAP_DEVICE_CAPS;

	return 0;
}

static int virtio_video_enum_fmt_vid_cap(struct file *file, void *fh,
					 struct v4l2_fmtdesc *f)
{
	struct virtio_video_stream *stream = file2stream(file);
	struct virtio_video_device *vvd = to_virtio_vd(stream->video_dev);

	if (f->type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE)
		return -EINVAL;

	if (f->index >= vvd->num_capture_formats)
		return -EINVAL;

	f->pixelformat = vvd->capture_fmts[f->index]->fourcc_format;

	return 0;
}

static struct video_pix_format *find_pix_format(struct video_pix_format **list,
						uint32_t fourcc, int num)
{
	int idx = 0;

	for (idx = 0; idx < num; idx++) {
		if (list[idx]->fourcc_format == fourcc)
			return list[idx];
	}
	return NULL;
}

static int virtio_video_try_decoder_cmd(struct file *file, void *fh,
					struct v4l2_decoder_cmd *cmd)
{
	struct virtio_video_stream *stream = file2stream(file);
	struct virtio_video_device *vvd = video_drvdata(file);
	struct virtio_video *vv = vvd->vv;

	if (stream->state == STREAM_STATE_DRAIN)
		return -EBUSY;

	switch (cmd->cmd) {
	case V4L2_DEC_CMD_STOP:
	case V4L2_DEC_CMD_START:
		if (cmd->flags != 0) {
			v4l2_err(&vv->v4l2_dev, "flags=%u are not supported",
				 cmd->flags);
			return -EINVAL;
		}
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int virtio_video_decoder_cmd(struct file *file, void *fh,
				    struct v4l2_decoder_cmd *cmd)
{
	int ret;
	struct vb2_queue *src_vq, *dst_vq;
	struct virtio_video_stream *stream = file2stream(file);
	struct virtio_video_device *vvd = video_drvdata(file);
	struct virtio_video *vv = vvd->vv;

	ret = virtio_video_try_decoder_cmd(file, fh, cmd);
	if (ret < 0)
		return ret;

	dst_vq = v4l2_m2m_get_vq(stream->fh.m2m_ctx,
				 V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE);

	switch (cmd->cmd) {
	case V4L2_DEC_CMD_START:
		vb2_clear_last_buffer_dequeued(dst_vq);
		ret = virtio_video_req_stream_start(vv, vvd->id,
						    stream->stream_id);
		if (ret)
			return ret;
		break;
	case V4L2_DEC_CMD_STOP:
		src_vq = v4l2_m2m_get_vq(stream->fh.m2m_ctx,
					 V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE);

		if (!vb2_is_streaming(src_vq)) {
			v4l2_dbg(1, vv->debug,
				 &vv->v4l2_dev, "output is not streaming\n");
			return 0;
		}

		if (!vb2_is_streaming(dst_vq)) {
			v4l2_dbg(1, vv->debug,
				 &vv->v4l2_dev, "capture is not streaming\n");
			return 0;
		}

		ret = virtio_video_req_stream_drain(vv, vvd->id,
						    stream->stream_id);
		if (ret) {
			v4l2_err(&vv->v4l2_dev, "failed to drain stream\n");
			return ret;
		}
		stream->state = STREAM_STATE_DRAIN;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int virtio_video_enum_framesizes(struct file *file, void *fh,
					struct v4l2_frmsizeenum *f)
{
	struct virtio_video_stream *stream = file2stream(file);
	struct virtio_video_device *vvd = to_virtio_vd(stream->video_dev);
	struct video_frame_size *frame_size = NULL;
	int i = 0;
	bool fake_non_discrete = false;
	int idx = f->index;
	struct video_pix_format *fmt = NULL;

	fmt = find_pix_format(vvd->output_fmts, f->pixel_format,
			      vvd->num_output_formats);
	if (fmt == NULL)
		fmt = find_pix_format(vvd->capture_fmts, f->pixel_format,
				      vvd->num_capture_formats);
	if (fmt == NULL)
		return -EINVAL;

	if (idx >= fmt->num_sizes)
		return -EINVAL;

	/* If the index is 0 - it is the first call of ENUM_FRAMESIZES, that
	 * defines a type of all the frame sizes.
	 *
	 * Indexes > 0 can be used later only in case of the type is discrete.
	 * But, if there is at least one non-discrete type later in the array -
	 * it may be misinterpreted as a discrete one.
	 *
	 * Hence, check, whether there is a non-discrete frame size, and if yes
	 * - return the first of them.
	 */
	if (!idx)
		for (i = 0; i < fmt->num_sizes; i++) {
			frame_size = &fmt->frame_sizes[i];
			if (frame_size->min_width != frame_size->max_width ||
			    frame_size->min_height != frame_size->max_height) {
				idx = i;
				fake_non_discrete = true;
				break;
			}
		}

	/* Index > 0 can be used only for discrete frame sizes. Type of the
	 * frame sizes is equal to type of the first frame size.
	 */
	if (idx && !fake_non_discrete) {
		frame_size = &fmt->frame_sizes[0];
		if (frame_size->min_width != frame_size->max_width ||
		    frame_size->min_height != frame_size->max_height)
			return -EINVAL;
	}

	frame_size = &fmt->frame_sizes[idx];

	if (frame_size->min_width == frame_size->max_width &&
	   frame_size->min_height == frame_size->max_height) {
		f->type = V4L2_FRMSIZE_TYPE_DISCRETE;
		f->discrete.width = frame_size->min_width;
		f->discrete.height = frame_size->min_height;
	} else {
		if (idx && !fake_non_discrete)
			return -EINVAL;
		f->stepwise.min_width = frame_size->min_width;
		f->stepwise.min_height = frame_size->min_height;
		f->stepwise.step_height = frame_size->step_height;
		f->stepwise.step_width = frame_size->step_width;
		f->stepwise.max_height = frame_size->max_height;
		f->stepwise.max_width = frame_size->max_width;
		if (frame_size->step_width == 1 &&
		    frame_size->min_height == 1) {
			f->type = V4L2_FRMSIZE_TYPE_CONTINUOUS;
		} else {
			f->type = V4L2_FRMSIZE_TYPE_STEPWISE;
		}
	}

	return 0;
}

static bool in_stepped_interval(uint32_t int_start, uint32_t int_end,
				uint32_t step, uint32_t point)
{
	if (point < int_start || point > int_end)
		return false;

	if (step == 0 && int_start == int_end && int_start == point)
		return true;

	if (step != 0 && (point - int_start) % step == 0)
		return true;

	return false;
}

static int virtio_video_enum_framemintervals(struct file *file, void *fh,
					     struct v4l2_frmivalenum *f)
{
	struct virtio_video_stream *stream = file2stream(file);
	struct virtio_video_device *vvd = to_virtio_vd(stream->video_dev);
	struct video_frame_size *fsize = NULL;
	int fsize_idx = 0;
	int i = 0;
	bool fake_non_discrete = false;
	int idx = f->index;
	struct video_pix_format *fmt = NULL;
	struct video_frame_rate *frate = NULL;

	fmt = find_pix_format(vvd->output_fmts, f->pixel_format,
			      vvd->num_output_formats);
	if (fmt == NULL)
		fmt = find_pix_format(vvd->capture_fmts, f->pixel_format,
				      vvd->num_capture_formats);
	if (fmt == NULL)
		return -EINVAL;

	for (fsize_idx = 0; fsize_idx <= fmt->num_sizes; fsize_idx++) {
		fsize = &fmt->frame_sizes[fsize_idx];
		if (in_stepped_interval(fsize->min_width, fsize->max_width,
					fsize->step_width, f->width) &&
		   in_stepped_interval(fsize->min_height, fsize->max_height,
					fsize->step_height, f->height))
			break;
	}

	if (fsize == NULL)
		return -EINVAL;

	if (idx >= fsize->num_rates)
		return -EINVAL;

	/* If the index is 0 - it is the first call of ENUM_FRAMEIVALS, that
	 * defines a type of all the frame intervals.
	 *
	 * Indexes > 0 can be used later only in case of the type is discrete.
	 * But, if there is at least one non-discrete type later in the array -
	 * it may be misinterpreted as a discrete one.
	 *
	 * Hence, check, whether there is a non-discrete frame rate, and if yes
	 * - return the first of them.
	 */
	if (!idx)
		for (i = 0; i < fsize->num_rates; i++) {
			frate = &fsize->frame_rates[i];
			if (frate->min_rate != frate->max_rate) {
				fake_non_discrete = true;
				idx = i;
				break;
			}
		}

	/* Index > 0 can be used only for discrete frame rates. Type of the
	 * frame rate is equal to the type of the first frame size.
	 */
	if (idx && !fake_non_discrete) {
		frate = &fsize->frame_rates[0];
		if (frate->max_rate != frate->min_rate)
			return -EINVAL;
	}

	frate = &fsize->frame_rates[idx];
	if (frate->max_rate == frate->min_rate) {
		f->type = V4L2_FRMIVAL_TYPE_DISCRETE;
		f->discrete.numerator = 1;
		f->discrete.denominator = frate->max_rate;
	} else {
		if (idx && !fake_non_discrete)
			return -EINVAL;
		/* If A > B, then 1/A < 1/B, so max denominator = min_rate
		 * and vise versa
		 */
		f->stepwise.min.numerator = 1;
		f->stepwise.min.denominator = frate->max_rate;
		f->stepwise.max.numerator = 1;
		f->stepwise.max.denominator = frate->min_rate;
		f->stepwise.step.numerator = 1;
		f->stepwise.step.denominator = frate->step;
		if (frate->step == 1)
			f->type = V4L2_FRMIVAL_TYPE_CONTINUOUS;
		else
			f->type = V4L2_FRMIVAL_TYPE_STEPWISE;
	}

	return 0;
}

static int virtio_video_enum_fmt_vid_out(struct file *file, void *fh,
					 struct v4l2_fmtdesc *f)
{
	struct virtio_video_stream *stream = file2stream(file);
	struct virtio_video_device *vvd = to_virtio_vd(stream->video_dev);

	if (f->type != V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE)
		return -EINVAL;

	if (f->index >= vvd->num_output_formats)
		return -EINVAL;

	f->pixelformat = vvd->output_fmts[f->index]->fourcc_format;

	return 0;
}

static void fill_v4l2_format_from_info(struct video_format_info *info,
				       struct v4l2_pix_format_mplane *pix_mp)
{
	int i;

	pix_mp->width = info->frame_width;
	pix_mp->height = info->frame_height;
	pix_mp->field = V4L2_FIELD_NONE;
	pix_mp->colorspace = V4L2_COLORSPACE_REC709;
	pix_mp->xfer_func = 0;
	pix_mp->ycbcr_enc = 0;
	pix_mp->quantization = 0;
	memset(pix_mp->reserved, 0, sizeof(pix_mp->reserved));
	memset(pix_mp->plane_fmt[0].reserved, 0,
	       sizeof(pix_mp->plane_fmt[0].reserved));

	pix_mp->num_planes = info->num_planes;
	pix_mp->pixelformat = info->fourcc_format;

	for (i = 0; i < info->num_planes; i++) {
		pix_mp->plane_fmt[i].bytesperline =
					 info->plane_format[i].stride;
		pix_mp->plane_fmt[i].sizeimage =
					 info->plane_format[i].plane_size;
	}
}

static int virtio_video_g_fmt(struct virtio_video_stream *stream,
			      struct v4l2_format *f)
{
	struct v4l2_pix_format_mplane *pix_mp = &f->fmt.pix_mp;
	struct video_format_info *info;

	if (!V4L2_TYPE_IS_OUTPUT(f->type))
		info = &stream->out_info;
	else
		info = &stream->in_info;

	fill_v4l2_format_from_info(info, pix_mp);
	return 0;
}

static int virtio_video_g_fmt_vid_out(struct file *file, void *fh,
				      struct v4l2_format *f)
{
	return virtio_video_g_fmt(file2stream(file), f);
}

static int virtio_video_g_fmt_vid_cap(struct file *file, void *fh,
				      struct v4l2_format *f)
{
	return virtio_video_g_fmt(file2stream(file), f);
}

static inline bool within_range(uint32_t min, uint32_t val, uint32_t max)
{
	return ((val - min) <= (max - min));
}

static inline bool needs_alignment(uint32_t val, uint32_t a)
{
	if (a == 0 || IS_ALIGNED(val, a))
		return false;

	return true;
}

static int virtio_video_try_fmt(struct virtio_video_stream *stream,
				struct v4l2_format *f)
{
	int i, idx = 0;
	struct v4l2_pix_format_mplane *pix_mp = &f->fmt.pix_mp;
	struct virtio_video_device *vvd = to_virtio_vd(stream->video_dev);
	struct video_pix_format *fmt = NULL;
	struct video_frame_size *frm_sz = NULL;
	bool found = false;

	if (V4L2_TYPE_IS_OUTPUT(f->type))
		fmt = find_pix_format(vvd->output_fmts, pix_mp->pixelformat,
					 vvd->num_output_formats);
	else
		fmt = find_pix_format(vvd->capture_fmts, pix_mp->pixelformat,
					 vvd->num_capture_formats);

	if (!fmt) {
		if (f->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE)
			fill_v4l2_format_from_info(&stream->out_info, pix_mp);
		else if (f->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE)
			fill_v4l2_format_from_info(&stream->in_info, pix_mp);
		else
			return -EINVAL;
		return 0;
	}

	for (i = 0; i < fmt->num_sizes && !found; i++) {
		frm_sz = &fmt->frame_sizes[i];
		if (!within_range(frm_sz->min_width, pix_mp->width,
				 frm_sz->max_width))
			continue;

		if (!within_range(frm_sz->min_height, pix_mp->height,
				  frm_sz->max_height))
			continue;

		idx = i;
		/*
		 * Try to find a more suitable frame size. Go with the current
		 * one otherwise.
		 */
		if (needs_alignment(pix_mp->width, frm_sz->step_width))
			continue;

		if (needs_alignment(pix_mp->height, frm_sz->step_height))
			continue;

		found = true;
	}

	if (!found) {
		frm_sz = &fmt->frame_sizes[idx];
		pix_mp->width = clamp(pix_mp->width, frm_sz->min_width,
				      frm_sz->max_width);
		if (frm_sz->step_width != 0)
			pix_mp->width = ALIGN(pix_mp->width,
					      frm_sz->step_width);

		pix_mp->height = clamp(pix_mp->height, frm_sz->min_height,
				      frm_sz->max_height);
		if (frm_sz->step_height != 0)
			pix_mp->height = ALIGN(pix_mp->height,
				       frm_sz->step_height);
	}

	return 0;
}

static int virtio_video_s_fmt(struct virtio_video_stream *stream,
			      struct v4l2_format *f)
{
	int i, ret;
	struct v4l2_pix_format_mplane *pix_mp = &f->fmt.pix_mp;
	struct virtio_video_device *vvd = to_virtio_vd(stream->video_dev);
	struct virtio_video *vv = vvd->vv;
	struct video_format_info info;
	struct video_format_info *p_info;
	enum video_pin_type pin = VIDEO_PIN_TYPE_INPUT;

	ret = virtio_video_try_fmt(stream, f);
	if (ret)
		return ret;

	info.frame_width = pix_mp->width;
	info.frame_height = pix_mp->height;
	info.num_planes = pix_mp->num_planes;
	info.fourcc_format = pix_mp->pixelformat;

	for (i = 0; i < info.num_planes; i++) {
		info.plane_format[i].stride =
					 pix_mp->plane_fmt[i].bytesperline;
		info.plane_format[i].plane_size =
					 pix_mp->plane_fmt[i].sizeimage;
	}

	if (!V4L2_TYPE_IS_OUTPUT(f->type))
		pin = VIDEO_PIN_TYPE_OUTPUT;

	virtio_video_req_set_params(vv, vvd->id, &info, pin,
				    VIDEO_PARAMS_SCOPE_STREAM, stream);

	virtio_video_req_get_params(vv, vvd->id, VIDEO_PIN_TYPE_INPUT,
				    VIDEO_PARAMS_SCOPE_STREAM, stream);

	virtio_video_req_get_params(vv, vvd->id, VIDEO_PIN_TYPE_OUTPUT,
				    VIDEO_PARAMS_SCOPE_STREAM, stream);

	if (V4L2_TYPE_IS_OUTPUT(f->type))
		p_info = &stream->in_info;
	else
		p_info = &stream->out_info;

	fill_v4l2_format_from_info(p_info, pix_mp);

	if (V4L2_TYPE_IS_OUTPUT(f->type)) {
		if (stream->state == STREAM_STATE_IDLE)
			stream->state = STREAM_STATE_INIT;
	}

	return 0;
}

static int virtio_video_s_fmt_vid_cap(struct file *file, void *fh,
				      struct v4l2_format *f)
{
	struct virtio_video_stream *stream = file2stream(file);

	return virtio_video_s_fmt(stream, f);
}

static int virtio_video_s_fmt_vid_out(struct file *file, void *fh,
				      struct v4l2_format *f)
{
	struct virtio_video_stream *stream = file2stream(file);

	return virtio_video_s_fmt(stream, f);
}

static int
virtio_video_subscribe_event(struct v4l2_fh *fh,
			     const struct v4l2_event_subscription *sub)
{
	switch (sub->type) {
	case V4L2_EVENT_SOURCE_CHANGE:
		return v4l2_src_change_event_subscribe(fh, sub);
	default:
		return -EINVAL;
	}
}

static const struct v4l2_ioctl_ops virtio_video_device_dec_ioctl_ops = {
	.vidioc_querycap	= virtio_video_querycap,

	.vidioc_enum_fmt_vid_cap = virtio_video_enum_fmt_vid_cap,
	.vidioc_g_fmt_vid_cap	= virtio_video_g_fmt_vid_cap,
	.vidioc_s_fmt_vid_cap	= virtio_video_s_fmt_vid_cap,

	.vidioc_g_fmt_vid_cap_mplane	= virtio_video_g_fmt_vid_cap,
	.vidioc_s_fmt_vid_cap_mplane	= virtio_video_s_fmt_vid_cap,

	.vidioc_enum_fmt_vid_out = virtio_video_enum_fmt_vid_out,
	.vidioc_g_fmt_vid_out	= virtio_video_g_fmt_vid_out,
	.vidioc_s_fmt_vid_out	= virtio_video_s_fmt_vid_out,

	.vidioc_g_fmt_vid_out_mplane	= virtio_video_g_fmt_vid_out,
	.vidioc_s_fmt_vid_out_mplane	= virtio_video_s_fmt_vid_out,

	.vidioc_try_decoder_cmd	= virtio_video_try_decoder_cmd,
	.vidioc_decoder_cmd	= virtio_video_decoder_cmd,
	.vidioc_enum_frameintervals = virtio_video_enum_framemintervals,
	.vidioc_enum_framesizes = virtio_video_enum_framesizes,

	.vidioc_reqbufs		= v4l2_m2m_ioctl_reqbufs,
	.vidioc_querybuf	= v4l2_m2m_ioctl_querybuf,
	.vidioc_qbuf		= v4l2_m2m_ioctl_qbuf,
	.vidioc_dqbuf		= v4l2_m2m_ioctl_dqbuf,
	.vidioc_prepare_buf	= v4l2_m2m_ioctl_prepare_buf,
	.vidioc_create_bufs	= v4l2_m2m_ioctl_create_bufs,
	.vidioc_expbuf		= v4l2_m2m_ioctl_expbuf,

	.vidioc_streamon	= v4l2_m2m_ioctl_streamon,
	.vidioc_streamoff	= v4l2_m2m_ioctl_streamoff,

	.vidioc_subscribe_event = virtio_video_subscribe_event,
	.vidioc_unsubscribe_event = v4l2_event_unsubscribe,
};

int virtio_video_dec_init(struct virtio_video_device *vvd)
{
	struct video_device *vd = NULL;

	if (!vvd)
		return -EINVAL;

	vd = &vvd->video_dev;
	vd->ioctl_ops = &virtio_video_device_dec_ioctl_ops;
	return 0;
}
