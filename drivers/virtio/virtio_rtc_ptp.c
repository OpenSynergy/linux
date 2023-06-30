// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Expose virtio_rtc clocks as PTP clocks.
 *
 * Copyright (C) 2022-2023 OpenSynergy GmbH
 *
 * Derived from ptp_kvm_common.c, virtual PTP 1588 clock for use with KVM
 * guests.
 *
 * Copyright (C) 2017 Red Hat Inc.
 */

#include <linux/device.h>
#include <linux/err.h>
#include <linux/ptp_clock_kernel.h>

#include <uapi/linux/virtio_rtc.h>

#include "virtio_rtc_internal.h"

/**
 * struct viortc_ptp_clock - PTP clock abstraction
 * @vio_clk_id: virtio_rtc clock id
 * @ptp_clock: PTP clock handle
 * @viortc: virtio_rtc device data
 * @ptp_info: PTP clock description
 * @num_hw_counters: actual # of hw_counters
 * @hw_counters: HW clocks which are supported for xtstamping
 */
struct viortc_ptp_clock {
	u64 vio_clk_id;
	struct ptp_clock *ptp_clock;
	struct viortc_dev *viortc;
	struct ptp_clock_info ptp_info;
	u32 num_hw_counters;
	u16 hw_counters[VIORTC_CAP_HW_COUNTERS];
};

/**
 * struct viortc_ptp_cross_ctx - context for get_device_system_crosststamp()
 * @device_time: device clock reading
 * @system_counterval: HW counter value at device_time
 *
 * Provides the already obtained crosststamp to get_device_system_crosststamp().
 */
struct viortc_ptp_cross_ctx {
	ktime_t device_time;
	struct system_counterval_t system_counterval;
};

/* Weak functions in case get_device_system_crosststamp() is not supported */

int __weak viortc_hw_get_counters(const u16 **hw_counters, int *num_hw_counters)
{
	*hw_counters = NULL;
	*num_hw_counters = 0;
	return 0;
}

int __weak viortc_hw_xtstamp_params(u16 *hw_counter, struct clocksource **cs)
{
	return -EOPNOTSUPP;
}

/**
 * viortc_ptp_get_time_fn() - callback for get_device_system_crosststamp()
 * @device_time: device clock reading
 * @system_counterval: HW counter value at device_time
 * @ctx: context with already obtained crosststamp
 *
 * Return: zero (success).
 */
static int viortc_ptp_get_time_fn(ktime_t *device_time,
				  struct system_counterval_t *system_counterval,
				  void *ctx)
{
	struct viortc_ptp_cross_ctx *vio_ctx = ctx;

	*device_time = vio_ctx->device_time;
	*system_counterval = vio_ctx->system_counterval;

	return 0;
}

/**
 * viortc_ptp_check_hw_counter_supported() - look up if xtstamp supported
 * @vio_ptp: virtio_rtc PTP clock
 * @hw_counter: virtio_rtc HW counter type
 *
 * Return: Zero if xtstamp is supported for hw_counter, negative error code
 *         otherwise.
 */
static int
viortc_ptp_check_hw_counter_supported(struct viortc_ptp_clock *vio_ptp,
				      u16 hw_counter)
{
	u32 i;

	for (i = 0; i < vio_ptp->num_hw_counters; i++) {
		if (vio_ptp->hw_counters[i] == hw_counter)
			return 0;
	}

	return -EOPNOTSUPP;
}

/**
 * viortc_ptp_do_xtstamp() - get HW-specific crosststamp from device
 * @vio_ptp: virtio_rtc PTP clock
 * @ctx: context for get_device_system_crosststamp()
 *
 * Gets HW-specific crosststamp params and reads crosststamp from device.
 *
 * Context: Process context.
 * Return: Zero on success, negative error code otherwise.
 */
static int viortc_ptp_do_xtstamp(struct viortc_ptp_clock *vio_ptp,
				 struct viortc_ptp_cross_ctx *ctx)
{
	u16 hw_counter;
	u64 ns;
	u64 max_ns;
	int ret;

	ret = viortc_hw_xtstamp_params(&hw_counter, &ctx->system_counterval.cs);
	if (ret)
		return ret;

	ret = viortc_ptp_check_hw_counter_supported(vio_ptp, hw_counter);
	if (ret)
		return ret;

	ret = viortc_read_cross(vio_ptp->viortc, vio_ptp->vio_clk_id,
				hw_counter, &ns,
				&ctx->system_counterval.cycles);
	if (ret)
		return ret;

	max_ns = (u64)ktime_to_ns(KTIME_MAX);
	if (ns > max_ns)
		return -EINVAL;

	ctx->device_time = ns_to_ktime(ns);

	return 0;
}

/*
 * PTP clock operations
 */

/**
 * viortc_ptp_getcrosststamp() - PTP clock getcrosststamp op
 * @vio_ptp: virtio_rtc PTP clock
 * @xtstamp: crosststamp
 *
 * Context: Process context.
 * Return: Zero on success, negative error code otherwise.
 */
static int viortc_ptp_getcrosststamp(struct ptp_clock_info *ptp,
				     struct system_device_crosststamp *xtstamp)
{
	struct viortc_ptp_clock *vio_ptp =
		container_of(ptp, struct viortc_ptp_clock, ptp_info);
	int ret;
	struct system_time_snapshot history_begin;
	struct viortc_ptp_cross_ctx ctx;

	ktime_get_snapshot(&history_begin);

	/*
	 * Getting the timestamp can take many milliseconds with a slow Virtio
	 * device. This is too long for viortc_ptp_get_time_fn() passed to
	 * get_device_system_crosststamp(), which has to usually return before
	 * the timekeeper seqcount increases (every tick or so).
	 *
	 * So, get the actual cross-timestamp first.
	 */
	ret = viortc_ptp_do_xtstamp(vio_ptp, &ctx);
	if (ret)
		return ret;

	ret = get_device_system_crosststamp(viortc_ptp_get_time_fn, &ctx,
					    &history_begin, xtstamp);
	if (ret) {
		pr_debug("%s: get_device_system_crosststamp() returned %d\n",
			 __func__, ret);
	}

	return ret;
}

/** viortc_ptp_adjfine() - unsupported PTP clock adjfine op */
static int viortc_ptp_adjfine(struct ptp_clock_info *ptp, long scaled_ppm)
{
	return -EOPNOTSUPP;
}

/** viortc_ptp_adjtime() - unsupported PTP clock adjtime op */
static int viortc_ptp_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	return -EOPNOTSUPP;
}

/** viortc_ptp_settime64() - unsupported PTP clock settime64 op */
static int viortc_ptp_settime64(struct ptp_clock_info *ptp,
				const struct timespec64 *ts)
{
	return -EOPNOTSUPP;
}

/**
 * viortc_ptp_gettimex64() - PTP clock gettimex64 op
 *
 * Context: Process context.
 */
static int viortc_ptp_gettimex64(struct ptp_clock_info *ptp,
				 struct timespec64 *ts,
				 struct ptp_system_timestamp *sts)
{
	struct viortc_ptp_clock *vio_ptp =
		container_of(ptp, struct viortc_ptp_clock, ptp_info);
	u64 ns;
	int ret;

	ptp_read_system_prets(sts);
	ret = viortc_read(vio_ptp->viortc, vio_ptp->vio_clk_id, &ns);
	ptp_read_system_postts(sts);

	if (ret)
		return ret;

	if (ns > (u64)S64_MAX)
		return -EINVAL;

	*ts = ns_to_timespec64((s64)ns);

	return 0;
}

/** viortc_ptp_enable() - unsupported PTP clock enable op */
static int viortc_ptp_enable(struct ptp_clock_info *ptp,
			     struct ptp_clock_request *rq, int on)
{
	return -EOPNOTSUPP;
}

/**
 * viortc_ptp_info_template - ptp_clock_info template
 *
 * The .name member will be set for individual virtio_rtc PTP clocks.
 */
static const struct ptp_clock_info viortc_ptp_info_template = {
	.owner = THIS_MODULE,
	/* .name is set according to clock type */
	.adjfine = viortc_ptp_adjfine,
	.adjtime = viortc_ptp_adjtime,
	.gettimex64 = viortc_ptp_gettimex64,
	.settime64 = viortc_ptp_settime64,
	.enable = viortc_ptp_enable,
	.getcrosststamp = viortc_ptp_getcrosststamp,
};

/**
 * viortc_ptp_unregister() - PTP clock unregistering wrapper
 * @vio_ptp: virtio_rtc PTP clock
 * @parent_dev: parent device of PTP clock
 *
 * Return: Zero on success, negative error code otherwise.
 */
int viortc_ptp_unregister(struct viortc_ptp_clock *vio_ptp,
			  struct device *parent_dev)
{
	int ret = ptp_clock_unregister(vio_ptp->ptp_clock);

	if (!ret)
		devm_kfree(parent_dev, vio_ptp);

	return ret;
}

/**
 * viortc_ptp_get_cross_cap() - get xtstamp support info from device
 * @viortc: virtio_rtc device data
 * @vio_ptp: virtio_rtc PTP clock abstraction
 *
 * Context: Process context.
 * Return: Zero on success, negative error code otherwise.
 */
static int viortc_ptp_get_cross_cap(struct viortc_dev *viortc,
				    struct viortc_ptp_clock *vio_ptp)
{
	int ret;
	const u16 *hw_counters_driver;
	u32 num_hw_counters_driver;
	u32 i;
	u32 num_hw_counters = 0;

	ret = viortc_hw_get_counters(&hw_counters_driver,
				     &num_hw_counters_driver);
	if (ret)
		return ret;

	if (num_hw_counters_driver > VIORTC_CAP_HW_COUNTERS) {
		pr_err("%s: HW counter capacity exceeded\n", __func__);
		return -ENOMEM;
	}

	for (i = 0; i < num_hw_counters_driver; i++) {
		u16 hw_counter = hw_counters_driver[i];
		bool xtstamp_supported;

		ret = viortc_cross_cap(viortc, vio_ptp->vio_clk_id, hw_counter,
				       &xtstamp_supported);
		if (ret)
			return ret;

		if (xtstamp_supported)
			vio_ptp->hw_counters[num_hw_counters++] = hw_counter;
	}

	vio_ptp->num_hw_counters = num_hw_counters;

	return 0;
}

/**
 * viortc_ptp_register() - prepare and register PTP clock
 * @viortc: virtio_rtc device data
 * @parent_dev: parent device for PTP clock
 * @vio_clk_id: id of virtio_rtc clock which backs PTP clock
 * @ptp_clock_name: PTP clock name
 * @try_enable_xtstamp: enable xtstamp op, if available
 *
 * Context: Process context.
 * Return: Pointer on success, ERR_PTR() otherwise; NULL if PTP clock support
 *         not available.
 */
struct viortc_ptp_clock *viortc_ptp_register(struct viortc_dev *viortc,
					     struct device *parent_dev,
					     u64 vio_clk_id,
					     const char *ptp_clock_name,
					     bool try_enable_xtstamp)
{
	struct viortc_ptp_clock *vio_ptp;
	struct ptp_clock *ptp_clock;
	ssize_t len;
	int ret;

	vio_ptp = devm_kzalloc(parent_dev, sizeof(*vio_ptp), GFP_KERNEL);
	if (!vio_ptp)
		return ERR_PTR(-ENOMEM);

	vio_ptp->viortc = viortc;
	vio_ptp->vio_clk_id = vio_clk_id;
	vio_ptp->ptp_info = viortc_ptp_info_template;
	len = strscpy(vio_ptp->ptp_info.name, ptp_clock_name,
		      sizeof(vio_ptp->ptp_info.name));
	if (len < 0) {
		ret = len;
		goto err_free_dev;
	}

	if (try_enable_xtstamp) {
		ret = viortc_ptp_get_cross_cap(viortc, vio_ptp);
		if (ret)
			goto err_free_dev;
	}

	ptp_clock = ptp_clock_register(&vio_ptp->ptp_info, parent_dev);
	if (IS_ERR(ptp_clock))
		goto err_on_register;

	vio_ptp->ptp_clock = ptp_clock;

	return vio_ptp;

err_on_register:
	ret = PTR_ERR(ptp_clock);

err_free_dev:
	devm_kfree(parent_dev, vio_ptp);
	return ERR_PTR(ret);
}
