// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Driver for virtio video device.
 *
 * Copyright 2020-2023 OpenSynergy GmbH.
 */

#include "virtio_video.h"

struct virtio_video_convert_table {
	uint32_t virtio_value;
	uint32_t v4l2_value;
};

static struct virtio_video_convert_table level_table[] = {
	{ VIRTIO_VIDEO_LEVEL_H264_1_0, V4L2_MPEG_VIDEO_H264_LEVEL_1_0 },
	{ VIRTIO_VIDEO_LEVEL_H264_1_1, V4L2_MPEG_VIDEO_H264_LEVEL_1_1 },
	{ VIRTIO_VIDEO_LEVEL_H264_1_2, V4L2_MPEG_VIDEO_H264_LEVEL_1_2 },
	{ VIRTIO_VIDEO_LEVEL_H264_1_3, V4L2_MPEG_VIDEO_H264_LEVEL_1_3 },
	{ VIRTIO_VIDEO_LEVEL_H264_2_0, V4L2_MPEG_VIDEO_H264_LEVEL_2_0 },
	{ VIRTIO_VIDEO_LEVEL_H264_2_1, V4L2_MPEG_VIDEO_H264_LEVEL_2_1 },
	{ VIRTIO_VIDEO_LEVEL_H264_2_2, V4L2_MPEG_VIDEO_H264_LEVEL_2_2 },
	{ VIRTIO_VIDEO_LEVEL_H264_3_0, V4L2_MPEG_VIDEO_H264_LEVEL_3_0 },
	{ VIRTIO_VIDEO_LEVEL_H264_3_1, V4L2_MPEG_VIDEO_H264_LEVEL_3_1 },
	{ VIRTIO_VIDEO_LEVEL_H264_3_2, V4L2_MPEG_VIDEO_H264_LEVEL_3_2 },
	{ VIRTIO_VIDEO_LEVEL_H264_4_0, V4L2_MPEG_VIDEO_H264_LEVEL_4_0 },
	{ VIRTIO_VIDEO_LEVEL_H264_4_1, V4L2_MPEG_VIDEO_H264_LEVEL_4_1 },
	{ VIRTIO_VIDEO_LEVEL_H264_4_2, V4L2_MPEG_VIDEO_H264_LEVEL_4_2 },
	{ VIRTIO_VIDEO_LEVEL_H264_5_0, V4L2_MPEG_VIDEO_H264_LEVEL_5_0 },
	{ VIRTIO_VIDEO_LEVEL_H264_5_1, V4L2_MPEG_VIDEO_H264_LEVEL_5_1 },
	{ 0 },
};

uint32_t virtio_video_level_to_v4l2(uint32_t level)
{
	size_t idx;

	for (idx = 0; idx < ARRAY_SIZE(level_table); idx++) {
		if (level_table[idx].virtio_value == level)
			return level_table[idx].v4l2_value;
	}

	return 0;
}

uint32_t virtio_video_v4l2_level_to_virtio(uint32_t v4l2_level)
{
	size_t idx;

	for (idx = 0; idx < ARRAY_SIZE(level_table); idx++) {
		if (level_table[idx].v4l2_value == v4l2_level)
			return level_table[idx].virtio_value;
	}

	return 0;
}

static struct virtio_video_convert_table profile_table[] = {
	{ VIRTIO_VIDEO_PROFILE_H264_BASELINE,
		V4L2_MPEG_VIDEO_H264_PROFILE_BASELINE },
	{ VIRTIO_VIDEO_PROFILE_H264_MAIN, V4L2_MPEG_VIDEO_H264_PROFILE_MAIN },
	{ VIRTIO_VIDEO_PROFILE_H264_EXTENDED,
		V4L2_MPEG_VIDEO_H264_PROFILE_EXTENDED },
	{ VIRTIO_VIDEO_PROFILE_H264_HIGH, V4L2_MPEG_VIDEO_H264_PROFILE_HIGH },
	{ VIRTIO_VIDEO_PROFILE_H264_HIGH10PROFILE,
		V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_10 },
	{ VIRTIO_VIDEO_PROFILE_H264_HIGH422PROFILE,
		V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_422},
	{ VIRTIO_VIDEO_PROFILE_H264_HIGH444PREDICTIVEPROFILE,
		V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_444_PREDICTIVE },
	{ VIRTIO_VIDEO_PROFILE_H264_SCALABLEBASELINE,
		V4L2_MPEG_VIDEO_H264_PROFILE_SCALABLE_BASELINE },
	{ VIRTIO_VIDEO_PROFILE_H264_SCALABLEHIGH,
		V4L2_MPEG_VIDEO_H264_PROFILE_SCALABLE_HIGH },
	{ VIRTIO_VIDEO_PROFILE_H264_STEREOHIGH,
		V4L2_MPEG_VIDEO_H264_PROFILE_STEREO_HIGH },
	{ VIRTIO_VIDEO_PROFILE_H264_MULTIVIEWHIGH,
		V4L2_MPEG_VIDEO_H264_PROFILE_MULTIVIEW_HIGH },
	{ 0 },
};

uint32_t virtio_video_profile_to_v4l2(uint32_t profile)
{
	size_t idx;

	for (idx = 0; idx < ARRAY_SIZE(profile_table); idx++) {
		if (profile_table[idx].virtio_value == profile)
			return profile_table[idx].v4l2_value;
	}

	return 0;
}

uint32_t virtio_video_v4l2_profile_to_virtio(uint32_t v4l2_profile)
{
	size_t idx;

	for (idx = 0; idx < ARRAY_SIZE(profile_table); idx++) {
		if (profile_table[idx].v4l2_value == v4l2_profile)
			return profile_table[idx].virtio_value;
	}

	return 0;
}

/* Unfortunately all necessary RGB formats definitions are not
 * available before kernel version 5.2. So for compatibility and
 * according to other available examples these formats are mapped
 * in a weird way:
 *   V4L2_PIX_FMT_ABGR32 -> BGRA 32 bit format
 *   V4L2_PIX_FMT_RGB32  -> RGBA 32 bit format.
 */
static struct virtio_video_convert_table format_table[] = {
	{ VIRTIO_VIDEO_FORMAT_ARGB8888, V4L2_PIX_FMT_ARGB32 },
	{ VIRTIO_VIDEO_FORMAT_BGRA8888, V4L2_PIX_FMT_ABGR32 },
	{ VIRTIO_VIDEO_FORMAT_RGBA8888, V4L2_PIX_FMT_RGB32 },
	{ VIRTIO_VIDEO_FORMAT_NV12, V4L2_PIX_FMT_NV12 },
	{ VIRTIO_VIDEO_FORMAT_YUV420, V4L2_PIX_FMT_YUV420 },
	{ VIRTIO_VIDEO_FORMAT_YVU420, V4L2_PIX_FMT_YVU420 },
	{ VIRTIO_VIDEO_FORMAT_YUV422, V4L2_PIX_FMT_YUYV },
	{ VIRTIO_VIDEO_FORMAT_MPEG2, V4L2_PIX_FMT_MPEG2 },
	{ VIRTIO_VIDEO_FORMAT_MPEG4, V4L2_PIX_FMT_MPEG4 },
	{ VIRTIO_VIDEO_FORMAT_H264, V4L2_PIX_FMT_H264 },
	{ VIRTIO_VIDEO_FORMAT_HEVC, V4L2_PIX_FMT_HEVC },
	{ VIRTIO_VIDEO_FORMAT_VP8, V4L2_PIX_FMT_VP8 },
	{ VIRTIO_VIDEO_FORMAT_VP9, V4L2_PIX_FMT_VP9 },
	{ 0 },
};

uint32_t virtio_video_format_to_v4l2(uint32_t format)
{
	size_t idx;

	for (idx = 0; idx < ARRAY_SIZE(format_table); idx++) {
		if (format_table[idx].virtio_value == format)
			return format_table[idx].v4l2_value;
	}

	return 0;
}

uint32_t virtio_video_v4l2_format_to_virtio(uint32_t v4l2_format)
{
	size_t idx;

	for (idx = 0; idx < ARRAY_SIZE(format_table); idx++) {
		if (format_table[idx].v4l2_value == v4l2_format)
			return format_table[idx].virtio_value;
	}

	return 0;
}

static struct virtio_video_convert_table control_table[] = {
	{ VIRTIO_VIDEO_CONTROL_BITRATE, V4L2_CID_MPEG_VIDEO_BITRATE },
	{ VIRTIO_VIDEO_CONTROL_PROFILE, V4L2_CID_MPEG_VIDEO_H264_PROFILE },
	{ VIRTIO_VIDEO_CONTROL_LEVEL, V4L2_CID_MPEG_VIDEO_H264_LEVEL },
	{ 0 },
};

uint32_t virtio_video_control_to_v4l2(uint32_t control)
{
	size_t idx;

	for (idx = 0; idx < ARRAY_SIZE(control_table); idx++) {
		if (control_table[idx].virtio_value == control)
			return control_table[idx].v4l2_value;
	}

	return 0;
}

uint32_t virtio_video_v4l2_control_to_virtio(uint32_t v4l2_control)
{
	size_t idx;

	for (idx = 0; idx < ARRAY_SIZE(control_table); idx++) {
		if (control_table[idx].v4l2_value == v4l2_control)
			return control_table[idx].virtio_value;
	}

	return 0;
}

struct video_format *virtio_video_find_video_format(struct list_head *fmts_list,
						    uint32_t format)
{
	struct video_format *fmt = NULL;

	list_for_each_entry(fmt, fmts_list, formats_list_entry) {
		if (fmt->desc.format == format)
			return fmt;
	}

	return NULL;
}

void virtio_video_format_from_info(struct video_format_info *info,
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

void virtio_video_format_fill_default_info(struct video_format_info *dst_info,
					  struct video_format_info *src_info)
{
	memcpy(dst_info, src_info, sizeof(*dst_info));
}

int virtio_video_frmsizeenum_from_fmt(struct video_format *fmt,
				      struct v4l2_frmsizeenum *f)
{
	struct video_format_frame *frm;
	struct virtio_video_format_frame *frame;
	int idx = f->index;

	if (fmt == NULL)
		return -EINVAL;

	if (idx < 0 || idx >= fmt->desc.num_frames)
		return -EINVAL;

	frm = &fmt->frames[idx];
	frame = &frm->frame;

	if (frame->width.min == frame->width.max &&
	    frame->height.min == frame->height.max) {
		f->type = V4L2_FRMSIZE_TYPE_DISCRETE;
		f->discrete.width = frame->width.min;
		f->discrete.height = frame->height.min;
		return 0;
	}

	f->type = V4L2_FRMSIZE_TYPE_CONTINUOUS;
	f->stepwise.min_width = frame->width.min;
	f->stepwise.max_width = frame->width.max;
	f->stepwise.min_height = frame->height.min;
	f->stepwise.max_height = frame->height.max;
	f->stepwise.step_width = frame->width.step;
	f->stepwise.step_height = frame->height.step;
	return 0;
}

static bool in_stepped_interval(struct virtio_video_format_range range,
				uint32_t point)
{
	if (point < range.min || point > range.max)
		return false;

	if (range.step == 0 && range.min == range.max && range.min == point)
		return true;

	if (range.step != 0 && (point - range.min) % range.step == 0)
		return true;

	return false;
}

int virtio_video_frmivalenum_from_fmt(struct video_format *fmt,
				      struct v4l2_frmivalenum *f)
{
	struct video_format_frame *frm;
	struct virtio_video_format_frame *frame = NULL;
	struct virtio_video_format_range *frate;
	int idx = f->index;
	int f_idx;

	if (fmt == NULL)
		return -EINVAL;

	if (idx < 0)
		return -EINVAL;

	for (f_idx = 0; f_idx < fmt->desc.num_frames; f_idx++) {
		frm = &fmt->frames[f_idx];
		frame = &frm->frame;
		if (in_stepped_interval(frame->width, f->width) &&
		    in_stepped_interval(frame->height, f->height))
			break;
	}

	if (frame == NULL || idx >= frame->num_rates)
		return -EINVAL;

	frate = &frm->frame_rates[idx];
	if (frate->max == frate->min) {
		f->type = V4L2_FRMIVAL_TYPE_DISCRETE;
		f->discrete.numerator = 1;
		f->discrete.denominator = frate->max;
	} else {
		f->stepwise.min.numerator = 1;
		f->stepwise.min.denominator = frate->max;
		f->stepwise.max.numerator = 1;
		f->stepwise.max.denominator = frate->min;
		f->stepwise.step.numerator = 1;
		f->stepwise.step.denominator = frate->step;
		if (frate->step == 1)
			f->type = V4L2_FRMIVAL_TYPE_CONTINUOUS;
		else
			f->type = V4L2_FRMIVAL_TYPE_STEPWISE;
	}
	return 0;
}

/** Find output video_format compatible with current stream input */
struct video_format *
virtio_video_find_compatible_output_format(struct virtio_video_stream *stream,
					   uint32_t fourcc_format)
{
	struct virtio_video_device *vvd = to_virtio_vd(stream->video_dev);
	struct video_format *fmt, *matching_fmt = NULL;
	unsigned long mask = 0;
	int bit_num = 0;

	fmt = virtio_video_find_video_format(&vvd->input_fmt_list,
					     stream->in_info.fourcc_format);
	if (fmt == NULL)
		return NULL;

	mask = fmt->desc.mask;
	list_for_each_entry(fmt, &vvd->output_fmt_list, formats_list_entry) {
		if (test_bit(bit_num, &mask)) {
			if (fmt->desc.format == fourcc_format) {
				matching_fmt = fmt;
				break;
			}
		}
		bit_num++;
	}

	return matching_fmt;
}

/** Find input video_format compatible with current stream output */
struct video_format *
virtio_video_find_compatible_input_format(struct virtio_video_stream *stream,
					  uint32_t fourcc_format)
{
	struct virtio_video_device *vvd = to_virtio_vd(stream->video_dev);
	struct video_format *fmt, *matching_fmt = NULL;
	unsigned long mask = 0;
	int bit_num = 0;

	fmt = virtio_video_find_video_format(&vvd->output_fmt_list,
					     stream->out_info.fourcc_format);
	if (fmt == NULL)
		return NULL;

	mask = fmt->desc.mask;
	list_for_each_entry(fmt, &vvd->input_fmt_list, formats_list_entry) {
		if (test_bit(bit_num, &mask)) {
			if (fmt->desc.format == fourcc_format) {
				matching_fmt = fmt;
				break;
			}
		}
		bit_num++;
	}

	return matching_fmt;
}
