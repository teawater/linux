// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 */

#include "bpf_experimental.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

#define LOOP_ITERS BPF_MAX_LOOPS

struct elem {
	struct bpf_thread_wq twq;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct elem);
} map_arr SEC(".maps");

volatile __u64 target_cgroup_id;
volatile __u64 twq_start_ns;
volatile __u64 twq_end_ns;
volatile int twq_done;

static int test_callback(__u32 index, void *data)
{
	return 0;
}

static int twq_callback(void *map, int *key, void *value)
{
	twq_start_ns = bpf_ktime_get_ns();
	bpf_loop(LOOP_ITERS, test_callback, NULL, 0);
	twq_end_ns = bpf_ktime_get_ns();
	bpf_printk("%lu\n", twq_end_ns - twq_start_ns);
	twq_done = 1;
	return 0;
}

SEC("syscall")
int start_thread_wq(void *ctx)
{
	struct elem *val;
	int key = 0;
	int ret;

	val = bpf_map_lookup_elem(&map_arr, &key);
	if (!val)
		return -1;

	if (!twq_done) {
		ret = bpf_thread_wq_init(&val->twq, &map_arr, target_cgroup_id, 0);
		if (ret)
			goto out;

		ret = bpf_thread_wq_set_callback(&val->twq, twq_callback, 0);
		if (ret)
			goto out;
	} else
		twq_done = 0;

	ret = bpf_thread_wq_start(&val->twq, 0);

out:
	return ret;
}
