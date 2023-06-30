/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * virtio_rtc internal interfaces
 *
 * Copyright (C) 2022-2023 OpenSynergy GmbH
 */

#ifndef _VIRTIO_RTC_INTERNAL_H_
#define _VIRTIO_RTC_INTERNAL_H_

#include <linux/types.h>
#include <linux/ptp_clock_kernel.h>

/* driver core IFs */

struct viortc_dev;

int viortc_read(struct viortc_dev *viortc, u64 vio_clk_id, u64 *reading);
int viortc_read_cross(struct viortc_dev *viortc, u64 vio_clk_id, u16 hw_counter,
		      u64 *reading, u64 *cycles);
int viortc_cross_cap(struct viortc_dev *viortc, u64 vio_clk_id, u16 hw_counter,
		     bool *supported);

/* PTP IFs */

struct viortc_ptp_clock;

#if IS_ENABLED(CONFIG_VIRTIO_RTC_PTP)

struct viortc_ptp_clock *viortc_ptp_register(struct viortc_dev *viortc,
					     struct device *parent_dev,
					     u64 vio_clk_id,
					     const char *ptp_clock_name,
					     bool try_enable_xtstamp);
int viortc_ptp_unregister(struct viortc_ptp_clock *vio_ptp,
			  struct device *parent_dev);

#else

static inline struct viortc_ptp_clock *
viortc_ptp_register(struct viortc_dev *viortc, struct device *parent_dev,
		    u64 vio_clk_id, const char *ptp_clock_name,
		    bool try_enable_xtstamp)
{
	return NULL;
}

int viortc_ptp_unregister(struct viortc_ptp_clock *vio_ptp,
			  struct device *parent_dev)
{
	return -ENODEV;
}

#endif

/* HW counter IFs */

/**
 * Maximum # of HW counters which the driver can support - can be increased.
 */
#define VIORTC_CAP_HW_COUNTERS 4

/**
 * viortc_hw_get_counters() - get HW counters present
 * @hw_counters: virtio_rtc HW counters
 * @num_hw_counters: number of HW counters
 *
 * num_hw_counters must not exceed VIORTC_CAP_HW_COUNTERS.
 *
 * Context: Process context.
 * Return: Zero on success, negative error code otherwise.
 */
int viortc_hw_get_counters(const u16 **hw_counters, int *num_hw_counters);

/**
 * viortc_hw_xtstamp_params() - get HW-specific xtstamp params
 * @hw_counter: virtio_rtc HW counter type
 * @cs: clocksource corresponding to hw_counter
 *
 * Context: Process context.
 * Return: Zero on success, negative error code otherwise.
 */
int viortc_hw_xtstamp_params(u16 *hw_counter, struct clocksource **cs);

#endif /* _VIRTIO_RTC_INTERNAL_H_ */
