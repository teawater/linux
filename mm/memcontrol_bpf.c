// SPDX-License-Identifier: GPL-2.0
/*
 * Memory Controller eBPF support
 *
 * Author: Hui Zhu <zhuhui@kylinos.cn>
 * Copyright (C) 2025 KylinSoft Corporation.
 */

#include <linux/cgroup-defs.h>
#include <linux/page_counter.h>
#include <linux/memcontrol.h>
#include <linux/cgroup.h>
#include <linux/rcupdate.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include "memcontrol_bpf.h"

DEFINE_SRCU(memcg_bpf_srcu);

void memcontrol_bpf_online(struct mem_cgroup *memcg)
{
	int idx;
	struct memcg_bpf_ops *ops;
	struct mem_cgroup *parent_memcg;

	if (mem_cgroup_is_root(memcg))
		return;
	parent_memcg = parent_mem_cgroup(memcg);

	idx = srcu_read_lock(&memcg_bpf_srcu);

	ops = READ_ONCE(parent_memcg->bpf_ops);
	if (!ops)
		goto out;

	WRITE_ONCE(memcg->bpf_ops, ops);

	if (!ops->handle_cgroup_online)
		goto out;

	ops->handle_cgroup_online(memcg);

out:
	srcu_read_unlock(&memcg_bpf_srcu, idx);
}

void memcontrol_bpf_offline(struct mem_cgroup *memcg)
{
	int idx;
	struct memcg_bpf_ops *ops;

	idx = srcu_read_lock(&memcg_bpf_srcu);

	ops = READ_ONCE(memcg->bpf_ops);
	if (!ops || !ops->handle_cgroup_offline)
		goto out;

	ops->handle_cgroup_offline(memcg);

out:
	srcu_read_unlock(&memcg_bpf_srcu, idx);
}

static int memcg_ops_btf_struct_access(struct bpf_verifier_log *log,
					const struct bpf_reg_state *reg,
					int off, int size)
{
	return -EACCES;
}

static bool memcg_ops_is_valid_access(int off, int size, enum bpf_access_type type,
	const struct bpf_prog *prog,
	struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

const struct bpf_verifier_ops bpf_memcg_verifier_ops = {
	.get_func_proto = bpf_base_func_proto,
	.btf_struct_access = memcg_ops_btf_struct_access,
	.is_valid_access = memcg_ops_is_valid_access,
};

static unsigned int cfi_memcg_nr_pages_over_high(struct mem_cgroup *memcg)
{
	return -EINVAL;
}

static void cfi_handle_cgroup_online(struct mem_cgroup *memcg)
{
}

static void cfi_handle_cgroup_offline(struct mem_cgroup *memcg)
{
}

static struct memcg_bpf_ops cfi_bpf_memcg_ops = {
	.memcg_nr_pages_over_high = cfi_memcg_nr_pages_over_high,
	.handle_cgroup_online = cfi_handle_cgroup_online,
	.handle_cgroup_offline = cfi_handle_cgroup_offline,
};

static int bpf_memcg_ops_init(struct btf *btf)
{
	return 0;
}

static int bpf_memcg_ops_check_member(const struct btf_type *t,
				const struct btf_member *member,
				const struct bpf_prog *prog)
{
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct memcg_bpf_ops, memcg_nr_pages_over_high):
		break;
	case offsetof(struct memcg_bpf_ops, handle_cgroup_online):
		break;
	case offsetof(struct memcg_bpf_ops, handle_cgroup_offline):
		break;
	default:
		if (prog->sleepable)
			return -EINVAL;
	}

	return 0;
}

static int bpf_memcg_ops_init_member(const struct btf_type *t,
				const struct btf_member *member,
				void *kdata, const void *udata)
{
	return 0;
}

static void clean_memcg_bpf_ops(struct mem_cgroup *memcg,
				struct memcg_bpf_ops *ops)
{
	struct mem_cgroup *iter = NULL;

	while ((iter = mem_cgroup_iter(memcg, iter, NULL))) {
		if (ops) {
			if (!WARN_ON(READ_ONCE(memcg->bpf_ops) != ops))
				WRITE_ONCE(memcg->bpf_ops, NULL);
		} else
			WRITE_ONCE(iter->bpf_ops, NULL);
	}
}

static int bpf_memcg_ops_reg(void *kdata, struct bpf_link *link)
{
	struct bpf_struct_ops_link *ops_link
		= container_of(link, struct bpf_struct_ops_link, link);
	struct memcg_bpf_ops *ops = kdata;
	struct mem_cgroup *memcg, *iter = NULL;
	int err = 0;

	memcg = mem_cgroup_get_from_ino(ops_link->cgroup_id);
	if (IS_ERR_OR_NULL(memcg))
		return PTR_ERR(memcg);

	cgroup_lock();
	while ((iter = mem_cgroup_iter(memcg, iter, NULL))) {
		if (READ_ONCE(iter->bpf_ops)) {
			mem_cgroup_iter_break(memcg, iter);
			err = -EBUSY;
			break;
		}

		WRITE_ONCE(iter->bpf_ops, ops);
	}
	if (err)
		clean_memcg_bpf_ops(memcg, NULL);
	cgroup_unlock();

	mem_cgroup_put(memcg);
	return err;
}

/* Unregister the struct ops instance */
static void bpf_memcg_ops_unreg(void *kdata, struct bpf_link *link)
{
	struct bpf_struct_ops_link *ops_link
		= container_of(link, struct bpf_struct_ops_link, link);
	struct memcg_bpf_ops *ops = kdata;
	struct mem_cgroup *memcg;

	memcg = mem_cgroup_get_from_ino(ops_link->cgroup_id);
	if (IS_ERR_OR_NULL(memcg))
		goto out;

	cgroup_lock();
	clean_memcg_bpf_ops(memcg, ops);
	cgroup_unlock();

	mem_cgroup_put(memcg);

out:
	synchronize_srcu(&memcg_bpf_srcu);
}

static struct bpf_struct_ops bpf_memcg_bpf_ops = {
	.verifier_ops = &bpf_memcg_verifier_ops,
	.init = bpf_memcg_ops_init,
	.check_member = bpf_memcg_ops_check_member,
	.init_member = bpf_memcg_ops_init_member,
	.reg = bpf_memcg_ops_reg,
	.unreg = bpf_memcg_ops_unreg,
	.name = "memcg_bpf_ops",
	.owner = THIS_MODULE,
	.cfi_stubs = &cfi_bpf_memcg_ops,
};

static int __init memcontrol_bpf_init(void)
{
	return register_bpf_struct_ops(&bpf_memcg_bpf_ops, memcg_bpf_ops);
}
late_initcall(memcontrol_bpf_init);
