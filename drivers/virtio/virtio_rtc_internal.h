/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * virtio_rtc internal interfaces
 *
 * Copyright (C) 2022-2023 OpenSynergy GmbH
 */

#ifndef _VIRTIO_RTC_INTERNAL_H_
#define _VIRTIO_RTC_INTERNAL_H_

#include <linux/types.h>

/* driver core IFs */

struct viortc_dev;

int viortc_read(struct viortc_dev *viortc, u64 vio_clk_id, u64 *reading);
int viortc_read_cross(struct viortc_dev *viortc, u64 vio_clk_id, u16 hw_counter,
		      u64 *reading, u64 *cycles);
int viortc_cross_cap(struct viortc_dev *viortc, u64 vio_clk_id, u16 hw_counter,
		     bool *supported);

#endif /* _VIRTIO_RTC_INTERNAL_H_ */
