/* SPDX-License-Identifier: ((GPL-2.0+ WITH Linux-syscall-note) OR BSD-3-Clause) */
/*
 * Copyright (C) 2022-2023 OpenSynergy GmbH
 */

#ifndef _LINUX_VIRTIO_RTC_H
#define _LINUX_VIRTIO_RTC_H

#include <linux/types.h>

/* read request message types */

#define VIRTIO_RTC_REQ_READ 0x0001
#define VIRTIO_RTC_REQ_READ_CROSS 0x0002

/* control request message types */

#define VIRTIO_RTC_REQ_CFG 0x1000
#define VIRTIO_RTC_REQ_CLOCK_CAP 0x1001
#define VIRTIO_RTC_REQ_CROSS_CAP 0x1002

/* Message headers */

/** common request header */
struct virtio_rtc_req_head {
	__le16 msg_type;
	__u8 reserved[6];
};

/** common response header */
struct virtio_rtc_resp_head {
#define VIRTIO_RTC_S_OK 0
#define VIRTIO_RTC_S_EOPNOTSUPP 2
#define VIRTIO_RTC_S_ENODEV 3
#define VIRTIO_RTC_S_EINVAL 4
#define VIRTIO_RTC_S_EIO 5
	__u8 status;
	__u8 reserved[7];
};

/* read requests */

/* VIRTIO_RTC_REQ_READ message */

struct virtio_rtc_req_read {
	struct virtio_rtc_req_head head;
	__le16 clock_id;
	__u8 reserved[6];
};

struct virtio_rtc_resp_read {
	struct virtio_rtc_resp_head head;
	__le64 clock_reading;
};

/* VIRTIO_RTC_REQ_READ_CROSS message */

struct virtio_rtc_req_read_cross {
	struct virtio_rtc_req_head head;
	__le16 clock_id;
/** Arm Generic Timer Virtual Count */
#define VIRTIO_RTC_COUNTER_ARM_VIRT 0
/** Arm Generic Timer Physical Count */
#define VIRTIO_RTC_COUNTER_ARM_PHYS 1
/** x86 Time Stamp Counter */
#define VIRTIO_RTC_COUNTER_X86_TSC 2
	__le16 hw_counter;
	__u8 reserved[4];
};

struct virtio_rtc_resp_read_cross {
	struct virtio_rtc_resp_head head;
	__le64 clock_reading;
	__le64 counter_cycles;
};

/* control requests */

/* VIRTIO_RTC_REQ_CFG message */

struct virtio_rtc_req_cfg {
	struct virtio_rtc_req_head head;
	/* no request params */
};

struct virtio_rtc_resp_cfg {
	struct virtio_rtc_resp_head head;
	/** # of clocks -> clock ids < num_clocks are valid */
	__le16 num_clocks;
	__u8 reserved[6];
};

/* VIRTIO_RTC_REQ_CLOCK_CAP message */

struct virtio_rtc_req_clock_cap {
	struct virtio_rtc_req_head head;
	__le16 clock_id;
	__u8 reserved[6];
};

struct virtio_rtc_resp_clock_cap {
	struct virtio_rtc_resp_head head;
#define VIRTIO_RTC_CLOCK_UTC 0
#define VIRTIO_RTC_CLOCK_TAI 1
#define VIRTIO_RTC_CLOCK_MONO 2
	__le16 type;
	__u8 reserved[6];
};

/* VIRTIO_RTC_REQ_CROSS_CAP message */

struct virtio_rtc_req_cross_cap {
	struct virtio_rtc_req_head head;
	__le16 clock_id;
	__le16 hw_counter;
	__u8 reserved[4];
};

struct virtio_rtc_resp_cross_cap {
	struct virtio_rtc_resp_head head;
#define VIRTIO_RTC_FLAG_CROSS_CAP (1 << 0)
	__u8 flags;
	__u8 reserved[7];
};

/** Union of request types for requestq */
union virtio_rtc_req_requestq {
	struct virtio_rtc_req_read read;
	struct virtio_rtc_req_read_cross read_cross;
	struct virtio_rtc_req_cfg cfg;
	struct virtio_rtc_req_clock_cap clock_cap;
	struct virtio_rtc_req_cross_cap cross_cap;
};

/** Union of response types for requestq */
union virtio_rtc_resp_requestq {
	struct virtio_rtc_resp_read read;
	struct virtio_rtc_resp_read_cross read_cross;
	struct virtio_rtc_resp_cfg cfg;
	struct virtio_rtc_resp_clock_cap clock_cap;
	struct virtio_rtc_resp_cross_cap cross_cap;
};

#endif /* _LINUX_VIRTIO_RTC_H */
