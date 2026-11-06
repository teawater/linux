// SPDX-License-Identifier: GPL-2.0
/*
 * The low_request policy for the memcg_ops_protection runner: count the
 * consultations about the victim cgroup, snapshot what the ctx carries,
 * and ask that the victim's current usage be protected.
 *
 * What the kernel does with that request is the point of the test: it is
 * arbitrated exactly like a declared memory.low, so the budget cgroup
 * above the victim decides whether the request is granted in full, cut
 * down, or - with nothing requested - ignored.  The runner varies the
 * budget and reads the effective value back from @pctx->threshold, which
 * carries the elow the previous reclaim pass computed.
 *
 * The snapshots are victim-scoped and, on top of that, filtered to the
 * reclaim the runner triggered: a request attached anywhere makes the
 * dispatcher run for every memcg, and global reclaim recalculates
 * protection with a NULL target, which would otherwise overwrite what
 * the triggered passes recorded.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

/* Set by the runner between open and load. */
__u64 target_cgroup_id;
__u64 parent_cgroup_id;

/*
 * Toggled by the runner between phases, before each trigger.  A map rather
 * than a global: .bss is frozen once the skeleton is loaded, so the runner
 * can only read it from here on.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} cfg SEC(".maps");

/* How often the kernel consulted us about the victim. */
__u64 low_calls;

/* Passes that recorded a snapshot; the runner brackets each trigger. */
__u64 record_seq;

/* Last snapshot from a runner-triggered pass. */
__u64 seen_threshold;
__u64 seen_usage;
int saw_from_parent;

/* BPF_PROG() uses "ctx" for the raw argument array, hence "pctx" here. */
SEC("struct_ops")
__u32 BPF_PROG(prot_low_request, const struct bpf_memcg_prot_ctx *pctx)
{
	__u32 key = 0, *enabled;

	if (pctx->cgroup_id != target_cgroup_id)
		return BPF_MEMCG_PROT_NO_REQUEST;

	__sync_fetch_and_add(&low_calls, 1);

	if (pctx->target_cgroup_id == parent_cgroup_id) {
		saw_from_parent = 1;
		seen_threshold = pctx->threshold;
		seen_usage = pctx->usage;
		__sync_fetch_and_add(&record_seq, 1);
	}

	enabled = bpf_map_lookup_elem(&cfg, &key);
	if (!enabled || !*enabled)
		return BPF_MEMCG_PROT_NO_REQUEST;

	return BPF_MEMCG_PROT_REQUEST_USAGE;
}

SEC(".struct_ops.link")
struct bpf_memcg_ops prot_ops = {
	.low_request = (void *)prot_low_request,
};
