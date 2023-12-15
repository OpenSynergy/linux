# SPDX-License-Identifier: GPL-2.0-or-later

# During development, to turn-off treating warning as error, pass
# `CFLAGS_MODULE=-Wno-error` to make as an argument or environment variable.
ccflags-y += -Werror

obj-$(CONFIG_VIRTIO_VIDEO) += virtio-video.o

virtio-video-objs := \
    virtio_video_driver.o \
    virtio_video_device.o \
    virtio_video_vq.o \
    virtio_video_dec.o \
    virtio_video_enc.o \
    virtio_video_caps.o \
    virtio_video_helpers.o
