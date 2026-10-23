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
 * What a policy can ask for when the kernel checks memory.low or memory.min
 * protection.  The kernel ORs them, so one policy cannot undo another.
 */
enum bpf_memcg_prot_request {
	BPF_MEMCG_PROT_NO_OPINION	= 0,
	/*
	 * Treat the cgroup as below its threshold, so reclaim skips it.  This
	 * only adds protection: a policy cannot expose a cgroup the kernel
	 * already considers below its threshold.
	 */
	BPF_MEMCG_PROT_BELOW		= 1U << 0,
};

#define BPF_MEMCG_PROT_VALID_MASK	BPF_MEMCG_PROT_BELOW

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
 * Read-only snapshot of a protection check.  @threshold is the effective
 * memory.low for low_policy and the effective memory.min for min_policy, and
 * the kernel has already found it below @usage.
 */
struct bpf_memcg_prot_ctx {
	struct mem_cgroup	*memcg;			/* cgroup checked */
	struct mem_cgroup	*target;		/* NULL for global reclaim */
	struct task_struct	*task;			/* current */
	u64			cgroup_id;
	u64			target_cgroup_id;	/* 0 if none */
	u64			threshold;		/* elow or emin, pages */
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
	 * low_policy - say whether a cgroup is below its memory.low
	 * @ctx: snapshot of the protection check
	 *
	 * Only runs once the kernel has found @ctx->usage above
	 * @ctx->threshold, so a policy can only add protection.  Reclaim then
	 * treats the cgroup as below memory.low throughout, which includes
	 * counting it in memory.events.
	 *
	 * Return: bits from enum bpf_memcg_prot_request, or 0.  Other bits
	 * are dropped.
	 */
	u32 (*low_policy)(const struct bpf_memcg_prot_ctx *ctx);

	/**
	 * min_policy - say whether a cgroup is below its memory.min
	 * @ctx: snapshot of the protection check
	 *
	 * Same as low_policy, for the hard memory.min protection.
	 *
	 * Return: bits from enum bpf_memcg_prot_request, or 0.  Other bits
	 * are dropped.
	 */
	u32 (*min_policy)(const struct bpf_memcg_prot_ctx *ctx);
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
 * Run every low_policy or min_policy on @memcg's cgroup and its ancestors,
 * and return the combined request for the caller to act on.
 *
 * @memcg:	the memcg whose protection is being checked, never the root
 * @target:	the reclaim root, or NULL for global reclaim
 * @elow/@emin:	the effective threshold, in pages
 * @usage:	the current usage, in pages
 */
u32 bpf_memcg_low_policy(struct mem_cgroup *memcg, struct mem_cgroup *target,
			 unsigned long elow, unsigned long usage);
u32 bpf_memcg_min_policy(struct mem_cgroup *memcg, struct mem_cgroup *target,
			 unsigned long emin, unsigned long usage);

#else /* CONFIG_BPF_SYSCALL */

/* mm/bpf_memcontrol.c is only built with struct_ops support. */
static inline u32 bpf_memcg_high_policy(struct mem_cgroup *memcg,
					struct mem_cgroup *over_limit,
					gfp_t gfp_mask)
{
	return BPF_MEMCG_HIGH_NO_OPINION;
}

static inline u32 bpf_memcg_low_policy(struct mem_cgroup *memcg,
				       struct mem_cgroup *target,
				       unsigned long elow, unsigned long usage)
{
	return BPF_MEMCG_PROT_NO_OPINION;
}

static inline u32 bpf_memcg_min_policy(struct mem_cgroup *memcg,
				       struct mem_cgroup *target,
				       unsigned long emin, unsigned long usage)
{
	return BPF_MEMCG_PROT_NO_OPINION;
}

#endif /* CONFIG_BPF_SYSCALL */

#endif /* _LINUX_BPF_MEMCONTROL_H */
