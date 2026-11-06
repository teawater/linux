/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF policy hooks for the memory controller.
 *
 * A bpf_memcg_ops is attached to a cgroup.  A hook runs the policies of that
 * cgroup and of every ancestor, and the kernel combines what they return.
 * BPF only picks between things the kernel already does.
 */
#ifndef _LINUX_BPF_MEMCONTROL_H
#define _LINUX_BPF_MEMCONTROL_H

#include <linux/types.h>
#include <linux/gfp_types.h>

struct mem_cgroup;
struct task_struct;

/*
 * What a policy can ask for when a cgroup is over memory.high.  The kernel
 * ORs them, so one policy cannot undo another.
 */
enum bpf_memcg_high_request {
	BPF_MEMCG_HIGH_NO_OPINION	= 0,
	/*
	 * Skip the inline reclaim and throttle.  The debt is kept and paid on
	 * the way back to userspace, where no kernel locks are held.
	 */
	BPF_MEMCG_HIGH_DEFER_INLINE	= 1U << 0,
};

#define BPF_MEMCG_HIGH_VALID_MASK	BPF_MEMCG_HIGH_DEFER_INLINE

/*
 * What a policy can ask for when reclaim computes memory.low protection.
 * The kernel takes the requests of the cgroup and of every ancestor and acts
 * on the largest, so one policy cannot take back what another asked for, nor
 * what the user declared in memory.low.
 */
enum bpf_memcg_prot_request {
	BPF_MEMCG_PROT_NO_REQUEST	= 0,
	/*
	 * Ask that this cgroup's current usage be taken as its declared
	 * memory.low for this pass.  Arbitrated exactly like a declared
	 * value: capped by the parent's effective protection and shared
	 * with the siblings.
	 */
	BPF_MEMCG_PROT_REQUEST_USAGE	= 1U << 0,
};

#define BPF_MEMCG_PROT_VALID_MASK	BPF_MEMCG_PROT_REQUEST_USAGE

/* Read-only snapshot.  Only values the caller already has. */
struct bpf_memcg_ctx {
	struct mem_cgroup	*memcg;			/* charged memcg */
	struct mem_cgroup	*memcg_over_limit;	/* NULL if none found */
	struct task_struct	*task;			/* current */
	u64			cgroup_id;
	u64			over_limit_cgroup_id;	/* 0 if none */
	u64			nr_pages_over_high;
	u32			gfp_flags;
};

/*
 * Read-only snapshot taken while reclaim is about to compute memory.low
 * protection.  @threshold is the effective memory.low left behind by the
 * previous calculation, not what this pass will end up with - that also
 * depends on the request.
 */
struct bpf_memcg_prot_ctx {
	struct mem_cgroup	*memcg;			/* cgroup checked */
	struct mem_cgroup	*target;		/* NULL for global reclaim */
	struct task_struct	*task;			/* current */
	u64			cgroup_id;
	u64			target_cgroup_id;	/* 0 if none */
	u64			threshold;		/* previous elow, pages */
	u64			usage;			/* pages */
};

struct bpf_memcg_ops {
	/**
	 * high_policy - say where memory.high should be enforced
	 * @ctx: snapshot of the charge
	 *
	 * Return: bits from enum bpf_memcg_high_request, or 0.  Other bits
	 * are dropped.
	 */
	u32 (*high_policy)(const struct bpf_memcg_ctx *ctx);

	/**
	 * low_request - ask for memory.low protection for this pass
	 * @ctx: snapshot of the cgroup protection is about to be computed for
	 *
	 * Runs before the effective memory.low is calculated, for every cgroup
	 * reclaim visits, whether or not it is already protected.  What a
	 * policy asks for is arbitrated together with the memory.low declared
	 * by the cgroup and by its siblings, so a request can move protection
	 * around inside the parent's budget but can never take the subtree
	 * above what its parent affords.
	 *
	 * Only memory.low is covered for now; a memory.min counterpart is
	 * left for later.  Hard protection has no fallback once nothing else
	 * is reclaimable, so a request recomputed every pass needs more
	 * thought before it is safe.
	 *
	 * Return: bits from enum bpf_memcg_prot_request, or 0.  Other bits
	 * are dropped.
	 */
	u32 (*low_request)(const struct bpf_memcg_prot_ctx *ctx);
};

#if IS_ENABLED(CONFIG_BPF_SYSCALL)

/*
 * Run every high_policy on @memcg's cgroup and its ancestors, and return the
 * combined request for the caller to act on.
 *
 * @memcg:	the memcg being charged, never NULL
 * @over_limit:	first memcg found over memory.high or swap.high, or NULL
 * @gfp_mask:	the charge's gfp mask
 */
u32 bpf_memcg_high_policy(struct mem_cgroup *memcg,
			  struct mem_cgroup *over_limit, gfp_t gfp_mask);

/*
 * Run every low_request on @memcg's cgroup and its ancestors, and return the
 * protection they ask for, in pages: @usage if any of them requested it, 0 if
 * none did.  The caller feeds the result to page_counter_set_low_req() before
 * the effective value is computed.
 *
 * @memcg:	the memcg protection is about to be computed for, never the root
 * @target:	the reclaim root, or NULL for global reclaim
 * @usage:	the current usage, in pages
 */
unsigned long bpf_memcg_low_request(struct mem_cgroup *memcg,
				    struct mem_cgroup *target,
				    unsigned long usage);

#else /* CONFIG_BPF_SYSCALL */

/* mm/bpf_memcontrol.c is only built with struct_ops support. */
static inline u32 bpf_memcg_high_policy(struct mem_cgroup *memcg,
					struct mem_cgroup *over_limit,
					gfp_t gfp_mask)
{
	return BPF_MEMCG_HIGH_NO_OPINION;
}

static inline unsigned long bpf_memcg_low_request(struct mem_cgroup *memcg,
						  struct mem_cgroup *target,
						  unsigned long usage)
{
	return 0;
}

#endif /* CONFIG_BPF_SYSCALL */

#endif /* _LINUX_BPF_MEMCONTROL_H */
