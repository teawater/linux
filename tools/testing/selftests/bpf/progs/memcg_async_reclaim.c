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

#define __GFP_IO		((gfp_t)___GFP_IO)
#define __GFP_FS		((gfp_t)___GFP_FS)
#define __GFP_DIRECT_RECLAIM	((gfp_t)___GFP_DIRECT_RECLAIM)	/* Caller can reclaim */
#define __GFP_KSWAPD_RECLAIM	((gfp_t)___GFP_KSWAPD_RECLAIM)	/* kswapd can wake */
#define __GFP_RECLAIM	((gfp_t)(___GFP_DIRECT_RECLAIM | ___GFP_KSWAPD_RECLAIM))

#define GFP_KERNEL	(__GFP_RECLAIM | __GFP_IO | __GFP_FS)
#define CLOCK_MONOTONIC_ID	1
#define RECLAIM_PAGES		32
#define RECLAIM_MAX_ITER	16

/*
 * cgroup_id:             target cgroup to monitor and reclaim from.
 * event_delta_threshold: number of new memory.events "max" events
 *                        (MEMCG_MAX) accumulated within one check_ns
 *                        period above which the cgroup is considered
 *                        under enough pressure to proactively reclaim.
 * check_ns:              sampling period of the pressure timer.
 */
struct bpf_args_s {
	u64 cgroup_id;
	u64 event_delta_threshold;
	u64 check_ns;
};

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

static int get_cgroup_max_event(u64 cgroup_id, u64 *val)
{
	struct cgroup_memcg cm;

	if (get_cgroup_memcg_from_id(cgroup_id, &cm))
		return -1;

	*val = bpf_mem_cgroup_memory_events(cm.memcg, MEMCG_MAX);
	put_cgroup_memcg(&cm);

	return 0;
}

static int reclaim_cgroup(u64 cgroup_id, u64 reclaim_enabled)
{
	struct cgroup_memcg cm;
	int i;

	if (get_cgroup_memcg_from_id(cgroup_id, &cm))
		return 0;

	for (i = 0; i < RECLAIM_MAX_ITER; i++) {
		if (!reclaim_enabled)
			break;
		if (!bpf_try_to_free_mem_cgroup_pages(cm.memcg, RECLAIM_PAGES,
						      GFP_KERNEL, 0, -1))
			break;
	}
	put_cgroup_memcg(&cm);

	return 0;
}

/* bpf_wq based async reclaim */

struct wq_elem {
	struct bpf_timer timer;
	struct bpf_wq work;
	u64 prev_max_event;
	u64 reclaim_enabled;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct wq_elem);
} wq_map SEC(".maps");

static struct bpf_args_s wq_bpf_args;

static int async_free(void *map, int *key, void *value)
{
	struct wq_elem *elem = value;

	reclaim_cgroup(wq_bpf_args.cgroup_id, elem->reclaim_enabled);

	return 0;
}

static int wq_timer_cb(void *map, int *key, struct wq_elem *elem)
{
	u64 cur, delta;

	if (!get_cgroup_max_event(wq_bpf_args.cgroup_id, &cur)) {
		delta = cur - elem->prev_max_event;
		elem->prev_max_event = cur;

		if (delta >= wq_bpf_args.event_delta_threshold) {
			elem->reclaim_enabled = 1;
			bpf_wq_start(&elem->work, 0);
		} else {
			elem->reclaim_enabled = 0;
		}
	}

	bpf_timer_start(&elem->timer, wq_bpf_args.check_ns, 0);
	return 0;
}

SEC("syscall")
int wq_prog_init(struct bpf_args_s *ctx)
{
	struct wq_elem *elem;
	__u32 key = 0;
	int ret;

	if (!ctx->cgroup_id || !ctx->check_ns)
		return -1;

	elem = bpf_map_lookup_elem(&wq_map, &key);
	if (!elem)
		return -1;

	ret = bpf_wq_init(&elem->work, &wq_map, 0);
	if (ret)
		return ret;

	ret = bpf_wq_set_callback(&elem->work, async_free, 0);
	if (ret)
		return ret;

	ret = bpf_timer_init(&elem->timer, &wq_map, CLOCK_MONOTONIC_ID);
	if (ret)
		return ret;

	ret = bpf_timer_set_callback(&elem->timer, wq_timer_cb);
	if (ret)
		return ret;

	elem->prev_max_event = 0;
	elem->reclaim_enabled = 0;

	wq_bpf_args.cgroup_id = ctx->cgroup_id;
	wq_bpf_args.event_delta_threshold = ctx->event_delta_threshold;
	wq_bpf_args.check_ns = ctx->check_ns;

	return bpf_timer_start(&elem->timer, wq_bpf_args.check_ns, 0);
}

/* bpf_thread_wq based async reclaim */

struct thread_wq_elem {
	struct bpf_timer timer;
	struct bpf_thread_wq work;
	u64 prev_max_event;
	u64 reclaim_enabled;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct thread_wq_elem);
} thread_wq_map SEC(".maps");

static struct bpf_args_s thread_wq_bpf_args;

static int thread_async_free(void *map, int *key, void *value)
{
	struct thread_wq_elem *elem = value;

	reclaim_cgroup(thread_wq_bpf_args.cgroup_id, elem->reclaim_enabled);

	return 0;
}

static int thread_wq_timer_cb(void *map, int *key, struct thread_wq_elem *elem)
{
	u64 cur, delta;

	if (!get_cgroup_max_event(thread_wq_bpf_args.cgroup_id, &cur)) {
		delta = cur - elem->prev_max_event;
		elem->prev_max_event = cur;

		if (delta >= thread_wq_bpf_args.event_delta_threshold) {
			elem->reclaim_enabled = 1;
			bpf_thread_wq_start(&elem->work, 0);
		} else {
			elem->reclaim_enabled = 0;
		}
	}

	bpf_timer_start(&elem->timer, thread_wq_bpf_args.check_ns, 0);
	return 0;
}

SEC("syscall")
int thread_wq_prog_init(struct bpf_args_s *ctx)
{
	struct thread_wq_elem *elem;
	__u32 key = 0;
	int ret;

	if (!ctx->cgroup_id || !ctx->check_ns)
		return -1;

	elem = bpf_map_lookup_elem(&thread_wq_map, &key);
	if (!elem)
		return -1;

	ret = bpf_thread_wq_init(&elem->work, &thread_wq_map, ctx->cgroup_id, 0);
	if (ret)
		return ret;

	ret = bpf_thread_wq_set_callback(&elem->work, thread_async_free, 0);
	if (ret)
		return ret;

	ret = bpf_timer_init(&elem->timer, &thread_wq_map, CLOCK_MONOTONIC_ID);
	if (ret)
		return ret;

	ret = bpf_timer_set_callback(&elem->timer, thread_wq_timer_cb);
	if (ret)
		return ret;

	elem->prev_max_event = 0;
	elem->reclaim_enabled = 0;

	thread_wq_bpf_args.cgroup_id = ctx->cgroup_id;
	thread_wq_bpf_args.event_delta_threshold = ctx->event_delta_threshold;
	thread_wq_bpf_args.check_ns = ctx->check_ns;

	return bpf_timer_start(&elem->timer, thread_wq_bpf_args.check_ns, 0);
}

char LICENSE[] SEC("license") = "GPL";
