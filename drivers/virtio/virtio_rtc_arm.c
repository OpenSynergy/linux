// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Provides cross-timestamp params for Arm.
 *
 * Copyright (C) 2022-2023 OpenSynergy GmbH
 */

#include <linux/clocksource_ids.h>

#include <uapi/linux/virtio_rtc.h>

#include "virtio_rtc_internal.h"

/* see header for doc */

int viortc_hw_xtstamp_params(u16 *hw_counter, enum clocksource_ids *cs_id)
{
	*hw_counter = VIRTIO_RTC_COUNTER_ARM_VIRT;
	*cs_id = CSID_ARM_ARCH_COUNTER;

	return 0;
}
