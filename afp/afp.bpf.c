// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static __s64 acc;
static u64 cg_id;

#define ONE_MB_PAGE_COUNT 256

SEC("tp_btf/mm_page_alloc")
int BPF_PROG(tp_page_alloc, struct page *page, unsigned int order,
	     gfp_t gfp_flags, int migratetype)
{
	struct cgroup_subsys_state *css;

	if (__sync_add_and_fetch(&acc, -(1L << order)) < ONE_MB_PAGE_COUNT)
		return 0;
	__sync_lock_release(&acc);

	

	return 0;
}

SEC("tp_btf/mm_page_free")
int BPF_PROG(tp_page_free, struct page *page, unsigned int order)
{
	__sync_add_and_fetch(&acc, (1L << order));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
