// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include "bpf_experimental.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define BIT(nr)			(1UL << (nr))

#define ___GFP_IO		BIT(___GFP_IO_BIT)
#define ___GFP_FS		BIT(___GFP_FS_BIT)
#define ___GFP_DIRECT_RECLAIM	BIT(___GFP_DIRECT_RECLAIM_BIT)
#define ___GFP_KSWAPD_RECLAIM	BIT(___GFP_KSWAPD_RECLAIM_BIT)

#define __GFP_IO	((gfp_t)___GFP_IO)
#define __GFP_FS	((gfp_t)___GFP_FS)
#define __GFP_DIRECT_RECLAIM	((gfp_t)___GFP_DIRECT_RECLAIM)
#define __GFP_KSWAPD_RECLAIM	((gfp_t)___GFP_KSWAPD_RECLAIM)
#define __GFP_RECLAIM	((gfp_t)(___GFP_DIRECT_RECLAIM | ___GFP_KSWAPD_RECLAIM))

#define GFP_KERNEL	(__GFP_RECLAIM | __GFP_IO | __GFP_FS)
#define CLOCK_MONOTONIC_ID 1

struct bpf_args_s {
	u64 high_cgroup_id;
	u64 low_cgroup_id;
	u64 period_ns;
	u64 pgfault_delta_threshold;
	u64 reclaim_pages;
} bpf_args;

struct reclaim_ctrl {
	struct bpf_timer timer;
	struct bpf_wq work;
	u64 prev_pgfault;
	u64 reclaim_enabled;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct reclaim_ctrl);
} reclaim_ctrl_map SEC(".maps");

struct cgroup_memcg {
	struct cgroup *cgrp;
	struct mem_cgroup *memcg;
};

static int get_cgroup_memcg_from_id(u64 cgroup_id, struct cgroup_memcg *cm)
{
	cm->cgrp = bpf_cgroup_from_id(cgroup_id);
	if (!cm->cgrp)
		return -1;

	cm->memcg = bpf_get_mem_cgroup(&cm->cgrp->self);
	if (!cm->memcg) {
		bpf_cgroup_release(cm->cgrp);
		return -1;
	}

	return 0;
}

static void put_cgroup_memcg(struct cgroup_memcg *cm)
{
	bpf_put_mem_cgroup(cm->memcg);
	bpf_cgroup_release(cm->cgrp);
}

#if 0
static int get_high_cgroup_pgfault(u64 *pgfault)
{
	struct cgroup_memcg cm;

	if (get_cgroup_memcg_from_id(bpf_args.high_cgroup_id, &cm))
		return -1;

	*pgfault = bpf_mem_cgroup_page_state(cm.memcg, PGSTEAL_DIRECT);
	put_cgroup_memcg(&cm);

	return 0;
}
#endif

static int reclaim_work_cb(void *map, int *key, void *value)
{
	struct reclaim_ctrl *ctrl = value;
	struct cgroup_memcg cm;
	int i;

	if (get_cgroup_memcg_from_id(bpf_args.low_cgroup_id, &cm))
		return 0;

	for (i = 0; i < 16; i++) {
		if (!ctrl->reclaim_enabled)
			break;
		if (!bpf_try_to_free_mem_cgroup_pages(cm.memcg,
						      bpf_args.reclaim_pages,
						      GFP_KERNEL, 0, -1))
			break;
		bpf_printk("r\n");
	}
	put_cgroup_memcg(&cm);

	if (ctrl->reclaim_enabled)
		bpf_wq_start(&ctrl->work, 0);

	return 0;
}

static int pressure_timer_cb(void *map, int *key, struct reclaim_ctrl *ctrl)
{
	//u64 pgfault = 0, delta = 0;

	bpf_printk("t\n");
	ctrl->reclaim_enabled = 1;
	bpf_wq_start(&ctrl->work, 0);

#if 0
	if (!get_high_cgroup_pgfault(&pgfault)) {
		bpf_printk("%lu %lu\n", ctrl->prev_pgfault, delta);
		delta = pgfault - ctrl->prev_pgfault;
		ctrl->prev_pgfault = pgfault;

		//bpf_printk("t%u\n", delta);
		if (delta >= bpf_args.pgfault_delta_threshold) {
			ctrl->reclaim_enabled = 1;
			bpf_wq_start(&ctrl->work, 0);
			//bpf_printk("t 1\n");
			bpf_printk("t%u\n", delta);
		} else {
			ctrl->reclaim_enabled = 0;
			//bpf_printk("t 2\n");
		}
	}
#endif

	bpf_timer_start(&ctrl->timer, bpf_args.period_ns, 0);
	return 0;
}

SEC("syscall")
int prog_init(struct bpf_args_s *ctx)
{
	struct reclaim_ctrl *ctrl;
	__u32 key = 0;
	int ret;

	if (!ctx->high_cgroup_id || !ctx->period_ns || !ctx->reclaim_pages)
		return -1;

	ctrl = bpf_map_lookup_elem(&reclaim_ctrl_map, &key);
	if (!ctrl)
		return -1;

	ret = bpf_wq_init(&ctrl->work, &reclaim_ctrl_map, 0);
	if (ret)
		return ret;

	ret = bpf_wq_set_callback(&ctrl->work, reclaim_work_cb, 0);
	if (ret)
		return ret;

	ret = bpf_timer_init(&ctrl->timer, &reclaim_ctrl_map,
			     CLOCK_MONOTONIC_ID);
	if (ret)
		return ret;

	ret = bpf_timer_set_callback(&ctrl->timer, pressure_timer_cb);
	if (ret)
		return ret;

	ctrl->prev_pgfault = 0;
	ctrl->reclaim_enabled = 0;

	bpf_args.high_cgroup_id = ctx->high_cgroup_id;
	bpf_args.low_cgroup_id = ctx->low_cgroup_id;
	bpf_args.period_ns = ctx->period_ns;
	bpf_args.pgfault_delta_threshold = ctx->pgfault_delta_threshold;
	bpf_args.reclaim_pages = ctx->reclaim_pages;

	return bpf_timer_start(&ctrl->timer, bpf_args.period_ns, 0);
}

char LICENSE[] SEC("license") = "GPL";
