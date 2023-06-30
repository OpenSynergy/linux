// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Provides cross-timestamp params for Arm.
 *
 * Copyright (C) 2022-2023 OpenSynergy GmbH
 */

#include <clocksource/arm_arch_timer.h>
#include <linux/err.h>

#include <uapi/linux/virtio_rtc.h>

#include "virtio_rtc_internal.h"

static const u16 viortc_hw_counters[] = { VIRTIO_RTC_COUNTER_ARM_VIRT,
					  VIRTIO_RTC_COUNTER_ARM_PHYS };

/* see header for doc */
int viortc_hw_get_counters(const u16 **hw_counters, int *num_hw_counters)
{
	*hw_counters = viortc_hw_counters;
	*num_hw_counters = ARRAY_SIZE(viortc_hw_counters);

	return 0;
}

/* see header for doc */
int viortc_hw_xtstamp_params(u16 *hw_counter, struct clocksource **cs)
{
	*cs = arch_timer_get_cs();

	switch (arch_timer_counter_get_type()) {
	case ARCH_COUNTER_CP15_VIRT:
		*hw_counter = VIRTIO_RTC_COUNTER_ARM_VIRT;
		break;
	case ARCH_COUNTER_CP15_PHYS:
		*hw_counter = VIRTIO_RTC_COUNTER_ARM_PHYS;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}
