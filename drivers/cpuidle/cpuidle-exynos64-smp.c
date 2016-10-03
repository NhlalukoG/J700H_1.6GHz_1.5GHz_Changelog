/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include <linux/cpu.h>
#include <linux/cpuidle.h>
#include <linux/cpumask.h>
#include <linux/cpu_pm.h>
#include <linux/kernel.h>
#include <linux/of.h>
#include <linux/reboot.h>
#include <linux/suspend.h>
#ifdef CONFIG_SEC_PM
#include <linux/moduleparam.h>
#endif

#include <asm/psci.h>
#include <asm/suspend.h>
#include <asm/tlbflush.h>

#include <mach/exynos-powermode-smp.h>

#include "cpuidle_profiler.h"
#include "of_idle_states.h"

#ifdef CONFIG_SEC_PM
#define CPUIDLE_ENABLE_MASK (ENABLE_C2 | ENABLE_C3_LPM)

static enum {
	ENABLE_C2	= BIT(0),
	ENABLE_C3_LPM	= BIT(1),
} enable_mask = CPUIDLE_ENABLE_MASK;

DEFINE_SPINLOCK(enable_mask_lock);

static int set_enable_mask(const char *val, const struct kernel_param *kp)
{
	int rv = param_set_uint(val, kp);
	unsigned long flags;

	pr_info("%s: enable_mask=0x%x\n", __func__, enable_mask);

	if (rv)
		return rv;

	spin_lock_irqsave(&enable_mask_lock, flags);

	if (!(enable_mask & ENABLE_C2)) {
		unsigned int cpuid = smp_processor_id();
		int i;
		for_each_online_cpu(i) {
			if (i == cpuid)
				continue;
			smp_send_reschedule(i);
		}
	}

	spin_unlock_irqrestore(&enable_mask_lock, flags);

	return 0;
}

static struct kernel_param_ops enable_mask_param_ops = {
	.set = set_enable_mask,
	.get = param_get_uint,
};

module_param_cb(enable_mask, &enable_mask_param_ops, &enable_mask, 0644);
MODULE_PARM_DESC(enable_mask, "bitmask for C states - C2, C3(LPM)");
#endif /* CONFIG_SEC_PM */

#ifdef CONFIG_SEC_PM_DEBUG
unsigned int log_en;
module_param_named(log_en, log_en, uint, 0644);
#endif /* CONFIG_SEC_PM_DEBUG */

enum idle_state {
	IDLE_C1 = 0,
	IDLE_C2,
	IDLE_CPD,
	IDLE_LPM,
};

static bool idle_c2_disabled(struct cpuidle_driver *drv)
{
	return drv->states[IDLE_C2].disabled;
}

static int find_next_state(struct cpuidle_device *dev,
			   struct cpuidle_driver *drv)
{
	int index;

	/* Search starts from the deepest idle state */
	for (index = IDLE_CPD; index >= IDLE_C2; index--) {
		struct cpuidle_state *s = &drv->states[index];
		struct cpuidle_state_usage *u = &dev->states_usage[index];

		if (s->disabled || u->disable)
			continue;

		return index;
	}

	return IDLE_C1;
}

static int exynos_enter_idle(struct cpuidle_device *dev,
			     struct cpuidle_driver *drv, int index)
{
	cpuidle_profile_start(dev->cpu, index);

	cpu_do_idle();

	cpuidle_profile_finish(dev->cpu, 0);

	return index;
}

static int exynos_enter_c2(struct cpuidle_device *dev,
			   struct cpuidle_driver *drv, int index)
{
	int cpu = dev->cpu, ret, target_index;
	unsigned int target_residency = drv->states[index].target_residency;

#ifdef CONFIG_SEC_PM_DEBUG
	if (unlikely(log_en & ENABLE_C2))
		pr_info("+++c2\n");
#endif

	ret = cpu_pm_enter();

	target_index = index;

	if (!ret) {
		target_index = determine_cpd(index, IDLE_C2, cpu, target_residency);

		if (target_index == IDLE_CPD)
			index |= CPD_STATE;
		cpuidle_profile_start(dev->cpu, index);

		ret = cpu_suspend(target_index);
		if (ret)
			flush_tlb_all();

		cpuidle_profile_finish(dev->cpu, ret);

		wakeup_from_c2(cpu);

		cpu_pm_exit();
	}

#ifdef CONFIG_SEC_PM_DEBUG
	if (unlikely(log_en & ENABLE_C2))
		pr_info("---c2\n");
#endif

	return ret ? -1 : target_index;
}

static int exynos_enter_lpm(struct cpuidle_device *dev,
			    struct cpuidle_driver *drv, int index)
{
	int ret, mode;
	int sub_state;

	mode = determine_lpm();

#ifdef CONFIG_SEC_PM_DEBUG
	if (unlikely(log_en & ENABLE_C3_LPM))
		pr_info("+++lpm:%d\n", mode);
#endif

	ret = cpu_pm_enter();

	if (!ret) {
		exynos_prepare_sys_powerdown(mode);

		sub_state = mode << LPM_SUB_STATE_OFFSET;
		cpuidle_profile_start(dev->cpu, index | sub_state);

		ret = cpu_suspend(index);
		if (ret)
			pr_info("cpuidle : early wakeup.\n");

		cpuidle_profile_finish(dev->cpu, ret);

		exynos_wakeup_sys_powerdown(mode, ret);

#ifdef CONFIG_SEC_PM_DEBUG
	if (unlikely(log_en & ENABLE_C3_LPM))
		pr_info("---lpm:%d\n", mode);
#endif

		cpu_pm_exit();
	}

	return ret ? -1 : index;
}

static int exynos_enter_idle_state(struct cpuidle_device *dev,
				   struct cpuidle_driver *drv, int index)
{
	int (*func)(struct cpuidle_device *, struct cpuidle_driver *, int);

#ifdef CONFIG_SEC_PM
	switch (index) {
	case IDLE_C2:
	case IDLE_CPD:
		if (unlikely(!(enable_mask & ENABLE_C2)))
			index = IDLE_C1;
		break;
	case IDLE_LPM:
		if (unlikely(!(enable_mask & ENABLE_C3_LPM))) {
			if (enable_mask & ENABLE_C2)
				index = IDLE_C2;
			else
				index = IDLE_C1;
		}
		break;
	default:
		break;
	}
#endif

	switch (index) {
	case IDLE_C1:
		func = exynos_enter_idle;
		break;
	case IDLE_C2:
	case IDLE_CPD:
		func = idle_c2_disabled(drv) ? exynos_enter_idle
					     : exynos_enter_c2;
		break;
	case IDLE_LPM:
		if (num_online_cpus() > 1) {
			index = find_next_state(dev, drv);
			return exynos_enter_idle_state(dev, drv, index);
		} else {
			func = exynos_enter_lpm;
			break;
		}
	default:
		pr_err("%s : invalid index: %d\n", __func__, index);
		return -EINVAL;
	}

	return (*func)(dev, drv, index);
}

static int exynos_cpuidle_pm_notifier(struct notifier_block *nb,
				      unsigned long event, void *unused)
{
	switch (event) {
	case PM_SUSPEND_PREPARE:
		cpu_idle_poll_ctrl(true);
		return NOTIFY_OK;
	case PM_POST_SUSPEND:
	case PM_POST_RESTORE:
		cpu_idle_poll_ctrl(false);
		return NOTIFY_OK;
	}

	return NOTIFY_DONE;
}

static struct notifier_block exynos_cpuidle_pm_nb = {
	.notifier_call = exynos_cpuidle_pm_notifier,
};

static int exynos_cpuidle_reboot_notifier(struct notifier_block *nb,
					  unsigned long event, void *unused)
{
	switch (event) {
	case SYS_RESTART:
	case SYSTEM_POWER_OFF:
		cpu_idle_poll_ctrl(true);
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block exynos_cpuidle_reboot_nb = {
	.notifier_call = exynos_cpuidle_reboot_notifier,
};

typedef int (*suspend_init_fn)(struct cpuidle_driver *,
			       struct device_node *[]);

struct cpu_suspend_ops {
	const char *id;
	suspend_init_fn init_fn;
};

static const struct cpu_suspend_ops suspend_operations[] __initconst = {
	{"arm,psci", psci_dt_register_idle_states},
	{}
};

static __init const struct cpu_suspend_ops *get_suspend_ops(const char *str)
{
	int i;

	if (!str)
		return NULL;

	for (i = 0; suspend_operations[i].id; i++)
		if (!strcmp(suspend_operations[i].id, str))
			return &suspend_operations[i];

	return NULL;
}

static DEFINE_PER_CPU(struct cpuidle_device, exynos64_cpuidle_device);

static struct cpuidle_driver exynos64_idle_driver = {
	.name  = "exynos64_idle",
	.owner = THIS_MODULE,
};

static struct device_node *state_nodes[CPUIDLE_STATE_MAX] __initdata;

static int __init exynos_idle_state_init(struct cpuidle_driver *idle_drv,
					 const struct cpumask *mask)
{
	int i, ret;
	const char *entry_method;
	struct device_node *idle_states_node;
	const struct cpu_suspend_ops *suspend_init;
	struct cpuidle_driver *drv = idle_drv;

	idle_states_node = of_find_node_by_path("/cpus/idle-states");
	if (!idle_states_node)
		return -ENOENT;

	if (of_property_read_string(idle_states_node, "entry-method",
				    &entry_method)) {
		pr_warn(" * %s missing entry-method property\n",
			    idle_states_node->full_name);
		of_node_put(idle_states_node);
		return -EOPNOTSUPP;
	}

	suspend_init = get_suspend_ops(entry_method);
	if (!suspend_init) {
		pr_warn("Missing suspend initializer\n");
		of_node_put(idle_states_node);
		return -EOPNOTSUPP;
	}

	drv->cpumask = (struct cpumask *)mask;

	ret = of_init_idle_driver(drv, state_nodes, 0, true);
	if (ret)
		return ret;

	if (suspend_init->init_fn(drv, state_nodes))
		return -EOPNOTSUPP;

	for (i = 0; i < drv->state_count; i++)
		drv->states[i].enter = exynos_enter_idle_state;

	return 0;
}

static int __init exynos64_init_cpuidle(void)
{
	int cpu, ret;
	struct cpuidle_device *device;

	ret = exynos_idle_state_init(&exynos64_idle_driver, cpu_online_mask);
	if (ret)
		return ret;

	cpuidle_profile_state_init(&exynos64_idle_driver);

	exynos64_idle_driver.safe_state_index = IDLE_C1;

	ret = cpuidle_register_driver(&exynos64_idle_driver);
	if (ret) {
		pr_err("cpuidle driver registeration failed\n");
		return ret;
	}

	for_each_cpu(cpu, cpu_online_mask) {
		device = &per_cpu(exynos64_cpuidle_device, cpu);
		device->cpu = cpu;

		device->state_count = exynos64_idle_driver.state_count;

		/* Non-boot cluster will skip idle time correlation */
		if (cpu & 0x4)
			device->skip_idle_correlation = true;
		else
			device->skip_idle_correlation = false;

		ret = cpuidle_register_device(device);
		if (ret) {
			pr_err("cpuidle device registeration failed\n");
			return ret;
		}
	}

	register_pm_notifier(&exynos_cpuidle_pm_nb);
	register_reboot_notifier(&exynos_cpuidle_reboot_nb);

	return 0;
}
device_initcall(exynos64_init_cpuidle);
