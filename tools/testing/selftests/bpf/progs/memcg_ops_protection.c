// SPDX-License-Identifier: GPL-2.0
/*
 * Watch the memory.low / memory.min policy hooks for the
 * memcg_ops_protection runner: count the consultations about the victim
 * cgroup and snapshot what the ctx carries.  Both members always say
 * NO_OPINION, so the kernel's own comparison decides and reclaim stays
 * free to take the cache; the runner only checks that the hooks ran and
 * saw sane values.
 *
 * The counters are victim-scoped on purpose: once any policy is attached
 * the dispatcher runs for every memcg, and background reclaim of unrelated
 * cgroups would otherwise drown the signal in noise.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

/* Set by the runner between open and load. */
__u64 target_cgroup_id;
__u64 parent_cgroup_id;

/* How often the kernel consulted us about the victim. */
__u64 min_calls;
__u64 low_calls;

/* Last victim-scoped snapshot, for checking what the ctx carries. */
__u64 seen_min_threshold;
__u64 seen_min_usage;
__u64 seen_low_threshold;
__u64 seen_low_usage;
int saw_min_from_parent;
int saw_low_from_parent;

/* BPF_PROG() uses "ctx" for the raw argument array, hence "mctx" here. */
SEC("struct_ops")
__u32 BPF_PROG(prot_min_policy, const struct bpf_memcg_prot_ctx *mctx)
{
	if (mctx->cgroup_id != target_cgroup_id)
		return BPF_MEMCG_PROT_NO_OPINION;

	__sync_fetch_and_add(&min_calls, 1);
	seen_min_threshold = mctx->threshold;
	seen_min_usage = mctx->usage;
	if (mctx->target_cgroup_id == parent_cgroup_id)
		saw_min_from_parent = 1;

	return BPF_MEMCG_PROT_NO_OPINION;
}

SEC("struct_ops")
__u32 BPF_PROG(prot_low_policy, const struct bpf_memcg_prot_ctx *mctx)
{
	if (mctx->cgroup_id != target_cgroup_id)
		return BPF_MEMCG_PROT_NO_OPINION;

	__sync_fetch_and_add(&low_calls, 1);
	seen_low_threshold = mctx->threshold;
	seen_low_usage = mctx->usage;
	if (mctx->target_cgroup_id == parent_cgroup_id)
		saw_low_from_parent = 1;

	return BPF_MEMCG_PROT_NO_OPINION;
}

SEC(".struct_ops.link")
struct bpf_memcg_ops prot_ops = {
	.low_policy = (void *)prot_low_policy,
	.min_policy = (void *)prot_min_policy,
};
