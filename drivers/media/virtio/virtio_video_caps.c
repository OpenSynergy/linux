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

#include <media/v4l2-ioctl.h>
#include <media/videobuf2-dma-sg.h>

#include "virtio_video.h"

static void pix_format_free(struct video_pix_format *pix_fmt)
{
	int size_idx = 0;

	if (!pix_fmt)
		return;

	for (size_idx = 0; size_idx < pix_fmt->num_sizes; size_idx++)
		kfree(pix_fmt->frame_sizes[size_idx].frame_rates);
	kfree(pix_fmt->frame_sizes);
}

static void fmt_capability_free(struct video_frame_format *frame_fmt)
{
	int fmt_idx = 0;

	if (!frame_fmt)
		return;

	for (fmt_idx = 0; fmt_idx < frame_fmt->num_formats; fmt_idx++)
		pix_format_free(&frame_fmt->pix_formats[fmt_idx]);
	kfree(frame_fmt->pix_formats);
}

static void ctrl_capability_free(struct video_controls *controls)
{
	if (!controls)
		return;

	kfree(controls->control);
}

static void capability_free(struct video_capability *cap)
{
	if (!cap)
		return;

	switch (cap->cap_type) {
	case VIRTIO_VIDEO_CAP_CONTROL:
		ctrl_capability_free(&cap->u.controls);
		break;
	case VIRTIO_VIDEO_CAP_PIN_FORMATS:
		fmt_capability_free(&cap->u.frame_format);
		break;
	default:
		return;
	}
	kfree(cap);
}

static size_t parse_virtio_frame_rate(struct video_frame_rate *frame_rate,
				      void *frame_rate_buf,
				      struct virtio_video_device *vvd)
{
	struct virtio_video *vv = NULL;
	struct virtio_video_frame_rate *virtio_frame_rate = NULL;
	size_t frame_rate_size = sizeof(struct virtio_video_frame_rate);

	if (!frame_rate || !frame_rate_buf || !vvd)
		return 0;

	vv = vvd->vv;
	virtio_frame_rate = frame_rate_buf;

	if (le32_to_cpu(virtio_frame_rate->desc.type) !=
	    VIRTIO_VIDEO_DESC_FRAME_RATE) {
		v4l2_err(&vv->v4l2_dev,
			 "failed to read frame rate descriptor\n");
		return 0;
	}

	frame_rate->min_rate = le32_to_cpu(virtio_frame_rate->min_rate);
	frame_rate->max_rate = le32_to_cpu(virtio_frame_rate->max_rate);
	frame_rate->step = le32_to_cpu(virtio_frame_rate->step);

	return frame_rate_size;
}

static size_t parse_virtio_frame_size(struct video_frame_size *frame_size,
				      void *frame_size_buf,
				      struct virtio_video_device *vvd)
{
	struct virtio_video *vv = NULL;
	size_t frame_size_size = 0;
	struct virtio_video_frame_size *virtio_frame_size = NULL;
	int rate_idx = 0;
	size_t offset = sizeof(struct virtio_video_frame_size);

	if (!frame_size || !frame_size_buf || !vvd)
		return 0;

	vv = vvd->vv;
	virtio_frame_size = frame_size_buf;

	if (le32_to_cpu(virtio_frame_size->desc.type) !=
	    VIRTIO_VIDEO_DESC_FRAME_SIZE) {
		v4l2_err(&vv->v4l2_dev,
			 "failed to read frame size descriptor\n");
		return 0;
	}

	frame_size->min_height = le32_to_cpu(virtio_frame_size->min_height);
	frame_size->max_height = le32_to_cpu(virtio_frame_size->max_height);
	frame_size->step_height = le32_to_cpu(virtio_frame_size->step_height);
	frame_size->min_width = le32_to_cpu(virtio_frame_size->min_width);
	frame_size->max_width = le32_to_cpu(virtio_frame_size->max_width);
	frame_size->step_width = le32_to_cpu(virtio_frame_size->step_width);
	frame_size->num_rates = le32_to_cpu(virtio_frame_size->num_rates);

	frame_size->frame_rates = kcalloc(frame_size->num_rates,
					  sizeof(struct video_frame_rate),
					  GFP_KERNEL);
	if (!frame_size->frame_rates) {
		v4l2_err(&vv->v4l2_dev, "failed to alloc frame rates\n");
		return 0;
	}

	for (rate_idx = 0; rate_idx < frame_size->num_rates; rate_idx++) {
		struct video_frame_rate *frame_rate =
			&frame_size->frame_rates[rate_idx];
		size_t rate_size = 0;

		rate_size = parse_virtio_frame_rate(frame_rate,
						    frame_size_buf + offset,
						    vvd);
		if (rate_size == 0) {
			v4l2_err(&vv->v4l2_dev, "failed to parse frame rate\n");
			kfree(frame_size->frame_rates);
			return 0;
		}
		offset += rate_size;
	}

	frame_size_size = offset;

	return frame_size_size;
}

static size_t parse_virtio_pix_fmt(struct video_pix_format *pix_fmt,
				   void *pix_buf,
				   struct virtio_video_device *vvd)
{
	struct virtio_video *vv = NULL;
	size_t pix_fmt_size = 0;
	struct virtio_video_pix_format *virtio_pix_fmt = NULL;
	int size_idx = 0;
	size_t offset = sizeof(struct virtio_video_pix_format);

	if (!pix_fmt || !pix_buf || !vvd)
		return 0;

	vv = vvd->vv;
	virtio_pix_fmt = pix_buf;

	if (le32_to_cpu(virtio_pix_fmt->desc.type) !=
	    VIRTIO_VIDEO_DESC_PIX_FORMAT) {
		v4l2_err(&vv->v4l2_dev, "failed to read pix fmt descriptor\n");
		return 0;
	}

	pix_fmt->fourcc_format =
			virtio_video_format_to_v4l2(
				le32_to_cpu(virtio_pix_fmt->pixel_format));
	pix_fmt->num_sizes = le32_to_cpu(virtio_pix_fmt->num_sizes);

	pix_fmt->frame_sizes = kcalloc(pix_fmt->num_sizes,
				       sizeof(struct video_frame_size),
				       GFP_KERNEL);
	if (!pix_fmt->frame_sizes) {
		v4l2_err(&vv->v4l2_dev, "failed to alloc frame sizes\n");
		return 0;
	}

	for (size_idx = 0; size_idx < pix_fmt->num_sizes; size_idx++) {
		struct video_frame_size *frame_size = NULL;
		size_t size_size = 0;

		frame_size = &pix_fmt->frame_sizes[size_idx];
		size_size = parse_virtio_frame_size(frame_size,
						    pix_buf + offset, vvd);
		if (size_size == 0) {
			v4l2_err(&vv->v4l2_dev, "failed to parse frame size\n");
			kfree(pix_fmt->frame_sizes);
			return 0;
		}
		offset += size_size;
	}

	pix_fmt_size = offset;

	return pix_fmt_size;
}

static size_t parse_virtio_fmts_cap(struct video_frame_format *frame_fmt,
				    void *cap_buf,
				    struct virtio_video_device *vvd)
{
	struct virtio_video *vv = NULL;
	size_t fmts_size = 0;
	struct virtio_video_frame_format *virtio_fmt = NULL;
	int fmt_idx = 0;
	size_t offset = sizeof(struct virtio_video_frame_format);
	struct virtio_video_capability dummy;

	if (!frame_fmt || !cap_buf || !vvd)
		return 0;

	vv = vvd->vv;
	virtio_fmt = cap_buf;

	frame_fmt->pin_type = le32_to_cpu(virtio_fmt->pin_type);
	frame_fmt->num_formats = le32_to_cpu(virtio_fmt->num_formats);

	frame_fmt->pix_formats = kcalloc(frame_fmt->num_formats,
					 sizeof(struct video_pix_format),
					 GFP_KERNEL);
	if (!frame_fmt->pix_formats) {
		v4l2_err(&vv->v4l2_dev, "failed to alloc pix formats\n");
		return 0;
	}

	for (fmt_idx = 0; fmt_idx < frame_fmt->num_formats; fmt_idx++) {
		struct video_pix_format *pix_fmt = NULL;
		size_t fmt_size = 0;

		pix_fmt = &frame_fmt->pix_formats[fmt_idx];
		fmt_size = parse_virtio_pix_fmt(pix_fmt, cap_buf + offset, vvd);
		if (fmt_size == 0) {
			v4l2_err(&vv->v4l2_dev,
				 "failed to parse pixel format\n");
			fmt_capability_free(frame_fmt);
			return 0;
		}
		offset += fmt_size;
	}

	switch (frame_fmt->pin_type) {
	case VIRTIO_VIDEO_PIN_INPUT:
		vvd->num_output_formats += frame_fmt->num_formats;
		break;
	case VIRTIO_VIDEO_PIN_OUTPUT:
		vvd->num_capture_formats += frame_fmt->num_formats;
		break;
	default:
		v4l2_err(&vv->v4l2_dev, "failed to parse a pin type\n");
		return 0;
	}

	fmts_size = offset - sizeof(dummy.u);

	return fmts_size;
}

static size_t parse_virtio_ctrl(struct video_control *control,
				void *control_buf,
				struct virtio_video_device *vvd)
{
	struct virtio_video *vv = NULL;
	struct virtio_video_control *virtio_control = NULL;
	size_t control_size = sizeof(struct virtio_video_control);

	if (!control || !control_buf || !vvd)
		return 0;

	vv = vvd->vv;
	virtio_control = control_buf;

	if (le32_to_cpu(virtio_control->desc.type) !=
	    VIRTIO_VIDEO_DESC_CONTROL) {
		v4l2_err(&vv->v4l2_dev, "failed to read control descriptor\n");
		return 0;
	}

	control->control_type =
		virtio_video_control_to_v4l2
		(le32_to_cpu(virtio_control->control_type));

	switch (control->control_type) {
	case V4L2_CID_MPEG_VIDEO_H264_PROFILE:
		control->min =
			virtio_video_profile_to_v4l2
			(le64_to_cpu(virtio_control->min));
		control->max =
			virtio_video_profile_to_v4l2
			(le64_to_cpu(virtio_control->max));
		control->step =
			virtio_video_profile_to_v4l2
			(le32_to_cpu(virtio_control->step));
		control->def =
			virtio_video_profile_to_v4l2
			(le64_to_cpu(virtio_control->def));
		break;
	case V4L2_CID_MPEG_VIDEO_H264_LEVEL:
		control->min =
			virtio_video_level_to_v4l2
			(le64_to_cpu(virtio_control->min));
		control->max =
			virtio_video_level_to_v4l2
			(le64_to_cpu(virtio_control->max));
		control->step =
			virtio_video_level_to_v4l2
			(le32_to_cpu(virtio_control->step));
		control->def =
			virtio_video_level_to_v4l2
			(le64_to_cpu(virtio_control->def));
		break;
	default:
		control->min = le64_to_cpu(virtio_control->min);
		control->max = le64_to_cpu(virtio_control->max);
		control->step = le32_to_cpu(virtio_control->step);
		control->def = le64_to_cpu(virtio_control->def);
		break;
	}

	return control_size;
}

static size_t parse_virtio_ctrls_cap(struct video_controls *controls,
				     void *cap_buf,
				     struct virtio_video_device *vvd)
{
	struct virtio_video_controls *virtio_controls = NULL;
	struct virtio_video *vv = NULL;
	size_t ctrls_size = 0;
	int ctrl_idx = 0;
	size_t offset = sizeof(struct virtio_video_controls);
	struct virtio_video_capability dummy;

	if (!controls || !cap_buf || !vvd)
		return 0;

	vv = vvd->vv;
	virtio_controls = cap_buf;

	controls->num_controls = le32_to_cpu(virtio_controls->num_controls);
	controls->control = kcalloc(controls->num_controls,
				    sizeof(struct video_control),
				    GFP_KERNEL);
	if (!controls->control) {
		v4l2_err(&vv->v4l2_dev, "failed to alloc controls\n");
		return 0;
	}

	for (ctrl_idx = 0; ctrl_idx < controls->num_controls; ctrl_idx++) {
		struct video_control *ctrl = NULL;
		size_t ctrl_size = 0;

		ctrl = &controls->control[ctrl_idx];
		ctrl_size = parse_virtio_ctrl(ctrl, cap_buf + offset, vvd);
		if (ctrl_size == 0) {
			v4l2_err(&vv->v4l2_dev, "failed to parse control\n");
			ctrl_capability_free(controls);
			return 0;
		}
		offset += ctrl_size;
	}

	ctrls_size = offset - sizeof(dummy.u);

	return ctrls_size;
}

static size_t parse_virtio_capability(struct video_capability *cap,
				      void *cap_buf,
				      struct virtio_video_device *vvd)
{
	struct virtio_video *vv = NULL;
	struct virtio_video_capability *virtio_cap = NULL;
	size_t offset = 0;
	size_t extra_size = 0;
	size_t cap_size = 0;

	if (!cap || !cap_buf || !vvd)
		return 0;

	vv = vvd->vv;
	virtio_cap = cap_buf;
	offset = sizeof(struct virtio_video_capability) - sizeof(virtio_cap->u);

	if (le32_to_cpu(virtio_cap->desc.type) != VIRTIO_VIDEO_DESC_CAP) {
		v4l2_err(&vv->v4l2_dev,
			 "failed to read capability descriptor\n");
		return 0;
	}

	cap->cap_id = le32_to_cpu(virtio_cap->cap_id);
	cap->cap_type = le32_to_cpu(virtio_cap->cap_type);

	switch (cap->cap_type) {
	case VIRTIO_VIDEO_CAP_CONTROL:
		extra_size = parse_virtio_ctrls_cap(&cap->u.controls,
						   cap_buf + offset, vvd);
		if (extra_size == 0) {
			v4l2_err(&vv->v4l2_dev, "failed to parse ctrl cap\n");
			return 0;
		}
		break;
	case VIRTIO_VIDEO_CAP_PIN_FORMATS:
		extra_size = parse_virtio_fmts_cap(&cap->u.frame_format,
						   cap_buf + offset, vvd);
		if (extra_size == 0) {
			v4l2_err(&vv->v4l2_dev, "failed to parse fmts cap\n");
			return 0;
		}
		break;
	default:
		v4l2_err(&vv->v4l2_dev, "undefined capability type\n");
		return 0;
	}

	if (extra_size < 0)
		extra_size = 0;

	cap_size = sizeof(struct virtio_video_capability) + extra_size;

	return cap_size;

}

void virtio_video_free_caps_list(struct list_head *caps_list)
{
	struct video_capability *cap = NULL;
	struct video_capability *tmp = NULL;

	list_for_each_entry_safe(cap, tmp, caps_list, caps_list_entry) {
		list_del(&cap->caps_list_entry);
		capability_free(cap);
	}

}

static int virtio_video_copy_params(struct video_format_info *dst,
				   const struct virtio_video_params *src)
{
	if (!dst || !src)
		return -EINVAL;

	dst->fourcc_format =
			virtio_video_format_to_v4l2(
				le32_to_cpu(src->pixel_format));
	dst->frame_height = le32_to_cpu(src->frame_height);
	dst->frame_width = le32_to_cpu(src->frame_width);
	dst->frame_rate = le32_to_cpu(src->frame_rate);
	dst->min_buffers = le32_to_cpu(src->min_buffers);
	return 0;
}

size_t virtio_video_parse_virtio_function(void *func_buf,
					  struct virtio_video_device *vvd)
{
	struct virtio_video *vv = NULL;
	size_t func_size = 0;
	struct virtio_video_function *virtio_func = NULL;
	uint32_t num_caps = 0;
	int cap_idx = 0;
	size_t offset = sizeof(struct virtio_video_function);
	struct video_capability *cap = NULL;
	int capture_idx = 0;
	int output_idx = 0;
	int ret = 0;

	if (!func_buf || !vvd)
		return 0;

	vv = vvd->vv;
	virtio_func = func_buf;

	if (le32_to_cpu(virtio_func->desc.type) != VIRTIO_VIDEO_DESC_FUNC) {
		v4l2_err(&vv->v4l2_dev, "failed to read function descriptor\n");
		return 0;
	}

	vvd->id = le32_to_cpu(virtio_func->function_id);
	vvd->type = le32_to_cpu(virtio_func->function_type);

	if (le32_to_cpu(virtio_func->in_params.desc.type) !=
	    VIRTIO_VIDEO_DESC_PARAMS) {
		v4l2_err(&vv->v4l2_dev, "failed to read function params\n");
		return 0;
	}

	ret = virtio_video_copy_params(&vvd->in_info,
					 &virtio_func->in_params);
	if (ret) {
		v4l2_err(&vv->v4l2_dev, "failed to read 'in' params\n");
		return 0;
	}

	if (le32_to_cpu(virtio_func->out_params.desc.type) !=
	    VIRTIO_VIDEO_DESC_PARAMS) {
		v4l2_err(&vv->v4l2_dev, "failed to read function params\n");
		return 0;
	}

	ret = virtio_video_copy_params(&vvd->out_info,
					 &virtio_func->out_params);
	if (ret) {
		v4l2_err(&vv->v4l2_dev, "failed to read 'out' params\n");
		return 0;
	}

	num_caps = le32_to_cpu(virtio_func->num_caps);

	for (cap_idx = 0; cap_idx < num_caps; cap_idx++) {
		size_t cap_size = 0;

		cap = kzalloc(sizeof(*cap), GFP_KERNEL);

		if (!cap) {
			virtio_video_free_caps_list(&vvd->ctrl_caps_list);
			virtio_video_free_caps_list(&vvd->fmt_caps_list);
			return 0;
		}

		cap_size = parse_virtio_capability(cap, func_buf + offset, vvd);
		if (cap_size == 0) {
			v4l2_err(&vv->v4l2_dev,
				 "failed to parse a capability\n");
			virtio_video_free_caps_list(&vvd->ctrl_caps_list);
			virtio_video_free_caps_list(&vvd->fmt_caps_list);
			kfree(cap);
			return 0;
		}
		offset += cap_size;

		switch (cap->cap_type) {
		case VIRTIO_VIDEO_CAP_PIN_FORMATS:
			list_add(&cap->caps_list_entry, &vvd->fmt_caps_list);
			break;
		case VIRTIO_VIDEO_CAP_CONTROL:
			list_add(&cap->caps_list_entry, &vvd->ctrl_caps_list);
			break;
		default:
			virtio_video_free_caps_list(&vvd->ctrl_caps_list);
			virtio_video_free_caps_list(&vvd->fmt_caps_list);
			capability_free(cap);
			break;
		}
	}

	vvd->capture_fmts = kcalloc(vvd->num_capture_formats,
				    sizeof(struct video_capability *),
				    GFP_KERNEL);
	vvd->output_fmts = kcalloc(vvd->num_output_formats,
				   sizeof(struct video_capability *),
				   GFP_KERNEL);
	if (!vvd->capture_fmts || !vvd->output_fmts) {
		v4l2_err(&vv->v4l2_dev, "failed to alloc capability arrays\n");
		virtio_video_free_caps_list(&vvd->ctrl_caps_list);
		virtio_video_free_caps_list(&vvd->fmt_caps_list);
	}

	cap = NULL;
	list_for_each_entry(cap, &vvd->fmt_caps_list, caps_list_entry) {
		struct video_frame_format *frame_fmt = &cap->u.frame_format;
		int pix_idx = 0;

		switch (le32_to_cpu(frame_fmt->pin_type)) {
		case VIRTIO_VIDEO_PIN_INPUT:
			for (pix_idx = 0; pix_idx < frame_fmt->num_formats;
			     pix_idx++) {
				vvd->output_fmts[pix_idx + output_idx] =
					&frame_fmt->pix_formats[pix_idx];
			}
			output_idx += pix_idx;
			break;
		case VIRTIO_VIDEO_PIN_OUTPUT:
			for (pix_idx = 0; pix_idx < frame_fmt->num_formats;
			     pix_idx++) {
				vvd->capture_fmts[pix_idx + capture_idx] =
					&frame_fmt->pix_formats[pix_idx];
			}
			capture_idx += pix_idx;
			break;
		default:
			v4l2_err(&vv->v4l2_dev, "failed to parse a pin type\n");
			return 0;
		}
	}

	func_size = offset;
	return func_size;
}

void virtio_video_clean_virtio_function(struct virtio_video_device *vvd)
{
	if (!vvd)
		return;

	kfree(vvd->capture_fmts);
	kfree(vvd->output_fmts);
	virtio_video_free_caps_list(&vvd->ctrl_caps_list);
	virtio_video_free_caps_list(&vvd->fmt_caps_list);
}
