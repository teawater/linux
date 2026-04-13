// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <string.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define BIT(nr)			(1UL << (nr))

#define ___GFP_IO		BIT(___GFP_IO_BIT)
#define ___GFP_FS		BIT(___GFP_FS_BIT)
#define ___GFP_DIRECT_RECLAIM	BIT(___GFP_DIRECT_RECLAIM_BIT)
#define ___GFP_KSWAPD_RECLAIM	BIT(___GFP_KSWAPD_RECLAIM_BIT)

#define __GFP_IO	((gfp_t)___GFP_IO)
#define __GFP_FS	((gfp_t)___GFP_FS)
#define __GFP_DIRECT_RECLAIM	((gfp_t)___GFP_DIRECT_RECLAIM) /* Caller can reclaim */
#define __GFP_KSWAPD_RECLAIM	((gfp_t)___GFP_KSWAPD_RECLAIM) /* kswapd can wake */
#define __GFP_RECLAIM ((gfp_t)(___GFP_DIRECT_RECLAIM|___GFP_KSWAPD_RECLAIM))

#define GFP_KERNEL	(__GFP_RECLAIM | __GFP_IO | __GFP_FS)

#define ONE_MB_PAGE_COUNT 256

struct bpf_args_s {
	u64 cgroup_id;
	u64 limit_bytes;
	u32 flags;
	s32 swappiness;
} bpf_args;

struct wq_elem {
	struct bpf_wq work;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct wq_elem);
} wq_map SEC(".maps");

static s64 allocated;
static u64 initialize_status = 1;

struct cgroup_memcg {
	struct cgroup *cgrp;
	struct mem_cgroup *memcg;
};

static int get_cgroup_memcg_from_id(u64 cgroup_id, struct cgroup_memcg *cm)
{
	cm->cgrp = bpf_cgroup_from_id(bpf_args.cgroup_id);
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

static int async_free(void *map, int *key, void *value)
{
	struct cgroup_memcg cm;

	if (get_cgroup_memcg_from_id(bpf_args.cgroup_id, &cm) != 0)
		return 0;

	if (bpf_try_to_free_mem_cgroup_pages(cm.memcg,
					     32, GFP_KERNEL,
					     bpf_args.flags,
					     bpf_args.swappiness) <= 0)
		goto out;

	if (bpf_mem_cgroup_usage(cm.memcg) >= bpf_args.limit_bytes) {
		__u32 key2 = 0;
		struct wq_elem *elem;

		elem = bpf_map_lookup_elem(&wq_map, &key2);
		if (!elem)
			goto out;
		bpf_wq_start(&elem->work, 0);
	}

out:
	put_cgroup_memcg(&cm);
	return 0;
}

SEC("syscall")
int prog_init(struct bpf_args_s *ctx)
{
	struct wq_elem *elem;
	__u32 key = 0;
	int ret;

	if (__atomic_fetch_add(&initialize_status, 1, __ATOMIC_ACQ_REL) != 1)
		return -1;

	elem = bpf_map_lookup_elem(&wq_map, &key);
	if (!elem)
		return -1;
	ret = bpf_wq_init(&elem->work, &wq_map, 0);
	if (ret)
		goto out;
	ret = bpf_wq_set_callback(&elem->work, async_free, 0);
	if (ret)
		goto out;

	allocated = 0;
	memcpy(&bpf_args, ctx, sizeof(bpf_args));

out:
	return ret;
}

static u64 get_usage(void)
{
	u64 ret = 0;
	struct cgroup_memcg cm;

	if (get_cgroup_memcg_from_id(bpf_args.cgroup_id, &cm) != 0)
		return 0;

	ret = bpf_mem_cgroup_usage(cm.memcg);

	put_cgroup_memcg(&cm);

	return ret;
}

SEC("tp_btf/mm_page_alloc")
int BPF_PROG(tp_page_alloc, struct page *page, unsigned int order,
	     gfp_t gfp_flags, int migratetype)
{
	struct wq_elem *elem;
	__u32 key = 0;
	s64 cur_allocated;

	if (bpf_get_current_cgroup_id() != bpf_args.cgroup_id)
		return 0;

	cur_allocated = __atomic_add_fetch(&allocated, 1L << order,
					   __ATOMIC_RELAXED);
	if ((cur_allocated & (ONE_MB_PAGE_COUNT - 1)) == 0)
		return 0;

	if (get_usage() < bpf_args.limit_bytes)
		return 0;

	elem = bpf_map_lookup_elem(&wq_map, &key);
	if (!elem)
		return 0;

	bpf_wq_start(&elem->work, 0);

	return 0;
}

SEC("tp_btf/mm_page_free")
int BPF_PROG(tp_page_free, struct page *page, unsigned int order)
{
	if (bpf_get_current_cgroup_id() != bpf_args.cgroup_id)
		return 0;

	__atomic_sub_fetch(&allocated, 1L << order, __ATOMIC_RELAXED);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
