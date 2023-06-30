/* SPDX-License-Identifier: ((GPL-2.0+ WITH Linux-syscall-note) OR BSD-3-Clause) */
/*
 * Copyright (C) 2022-2023 OpenSynergy GmbH
 */

#ifndef _LINUX_VIRTIO_RTC_H
#define _LINUX_VIRTIO_RTC_H

#include <linux/types.h>

/* Device-specific features */

#define VIRTIO_RTC_F_READ_CROSS 0

/* readq message types */

#define VIRTIO_RTC_M_READ 0x0001
#define VIRTIO_RTC_M_READ_CROSS 0x0002

/* controlq message types */

#define VIRTIO_RTC_M_CFG 0x1000
#define VIRTIO_RTC_M_CLOCK_CAP 0x1001
#define VIRTIO_RTC_M_CROSS_CAP 0x1002

/* Message headers */

/** common request header */
struct virtio_rtc_req_head {
	__le16 msg_type;
	__u8 reserved[2];
};

/** common response header */
struct virtio_rtc_resp_head {
#define VIRTIO_RTC_S_OK 0
#define VIRTIO_RTC_S_UNSUPP 1
#define VIRTIO_RTC_S_NODEV 2
#define VIRTIO_RTC_S_INVAL 3
#define VIRTIO_RTC_S_DEVERR 4
	__u8 status;
	__u8 reserved[3];
};

/* readq messages */

/* VIRTIO_RTC_M_READ message */

struct virtio_rtc_req_read {
	struct virtio_rtc_req_head head;
	__u8 reserved[4];
	__le64 clock_id;
};

struct virtio_rtc_resp_read {
	struct virtio_rtc_resp_head head;
	__u8 reserved[4];
	__le64 clock_reading;
};

/* VIRTIO_RTC_M_READ_CROSS message */

struct virtio_rtc_req_read_cross {
	struct virtio_rtc_req_head head;
/** Arm Generic Timer Virtual Count */
#define VIRTIO_RTC_COUNTER_ARM_VIRT 0
/** Arm Generic Timer Physical Count */
#define VIRTIO_RTC_COUNTER_ARM_PHYS 1
/** x86 Time Stamp Counter */
#define VIRTIO_RTC_COUNTER_X86_TSC 2
	__le16 hw_counter;
	__u8 reserved[2];
	__le64 clock_id;
};

struct virtio_rtc_resp_read_cross {
	struct virtio_rtc_resp_head head;
	__u8 reserved[4];
	__le64 clock_reading;
	__le64 counter_cycles;
};

/** Union of request types for readq */
union virtio_rtc_req_readq {
	struct virtio_rtc_req_read read;
	struct virtio_rtc_req_read_cross read_cross;
};

/** Union of response types for readq */
union virtio_rtc_resp_readq {
	struct virtio_rtc_resp_read read;
	struct virtio_rtc_resp_read_cross read_cross;
};

/* controlq messages */

/* VIRTIO_RTC_M_CFG message */

struct virtio_rtc_req_cfg {
	struct virtio_rtc_req_head head;
	/* no request params */
	__u8 reserved[4];
};

struct virtio_rtc_resp_cfg {
	struct virtio_rtc_resp_head head;
	/** # of clocks -> clock ids < num_clocks are valid */
	__le16 num_clocks;
	__u8 reserved[10];
};

/* VIRTIO_RTC_M_CLOCK_CAP message */

struct virtio_rtc_req_clock_cap {
	struct virtio_rtc_req_head head;
	__u8 reserved[4];
	__le64 clock_id;
};

struct virtio_rtc_resp_clock_cap {
	struct virtio_rtc_resp_head head;
#define VIRTIO_RTC_CLOCK_UTC 0
#define VIRTIO_RTC_CLOCK_TAI 1
#define VIRTIO_RTC_CLOCK_MONO 2
	__le16 type;
	__u8 reserved[10];
};

/* VIRTIO_RTC_M_CROSS_CAP message */

struct virtio_rtc_req_cross_cap {
	struct virtio_rtc_req_head head;
	__le16 hw_counter;
	__u8 reserved[2];
	__le64 clock_id;
};

struct virtio_rtc_resp_cross_cap {
	struct virtio_rtc_resp_head head;
#define VIRTIO_RTC_FLAG_CROSS_CAP 0
	__u8 flags;
	__u8 reserved[11];
};

/** Union of request types for controlq */
union virtio_rtc_req_controlq {
	struct virtio_rtc_req_cfg cfg;
	struct virtio_rtc_req_clock_cap clock_cap;
	struct virtio_rtc_req_cross_cap cross_cap;
};

/** Union of response types for controlq */
union virtio_rtc_resp_controlq {
	struct virtio_rtc_resp_cfg cfg;
	struct virtio_rtc_resp_clock_cap clock_cap;
	struct virtio_rtc_resp_cross_cap cross_cap;
};

#endif /* _LINUX_VIRTIO_RTC_H */
