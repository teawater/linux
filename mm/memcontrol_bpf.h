/* SPDX-License-Identifier: GPL-2.0-or-later */
/* memcontrol_bpf.h - Memory Controller eBPF support
 *
 * Author: Hui Zhu <zhuhui@kylinos.cn>
 * Copyright (C) 2025 KylinSoft Corporation.
 */

#ifndef _LINUX_MEMCONTROL_BPF_H
#define _LINUX_MEMCONTROL_BPF_H

#ifdef CONFIG_BPF_SYSCALL

struct memcg_bpf_ops {
	unsigned int (*memcg_nr_pages_over_high)(struct mem_cgroup *memcg);

	void (*handle_cgroup_online)(struct mem_cgroup *memcg);

	void (*handle_cgroup_offline)(struct mem_cgroup *memcg);
};

extern struct srcu_struct memcg_bpf_srcu;

static inline unsigned int
bpf_memcg_nr_pages_over_high(struct mem_cgroup *memcg)
{
	int idx;
	struct memcg_bpf_ops *ops;
	unsigned int nr_pages;

	idx = srcu_read_lock(&memcg_bpf_srcu);

	ops = READ_ONCE(memcg->bpf_ops);
	if (!ops || !ops->memcg_nr_pages_over_high)
		goto out;

	nr_pages = ops->memcg_nr_pages_over_high(memcg);

out:
	srcu_read_unlock(&memcg_bpf_srcu, idx);
	return nr_pages;
}

extern void memcontrol_bpf_online(struct mem_cgroup *memcg);
extern void memcontrol_bpf_offline(struct mem_cgroup *memcg);

#else

static inline unsigned int
bpf_memcg_nr_pages_over_high(struct mem_cgroup *memcg) { return 0 }
static inline void memcontrol_bpf_online(struct mem_cgroup *memcg) { }
static inline void memcontrol_bpf_offline(struct mem_cgroup *memcg) { }

#endif

#endif
