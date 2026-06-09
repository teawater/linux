// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 */

#include "bpf_experimental.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

#define LOOP_ITERS 500000

struct elem {
	struct bpf_wq wq;
	struct bpf_thread_wq twq;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct elem);
} map_arr SEC(".maps");

/* cgroup id to attach the bpf_thread_wq worker to */
volatile __u64 target_cgroup_id;

/* timestamps: start/end for bpf_wq and bpf_thread_wq callbacks */
volatile __u64 wq_start_ns;
volatile __u64 wq_end_ns;
volatile __u64 twq_start_ns;
volatile __u64 twq_end_ns;

/* completion flags */
volatile int wq_done;
volatile int twq_done;

/* error reporting */
volatile int err_wq;
volatile int err_twq;

static int empty_callback(__u32 index, void *data)
{
	return 0;
}

/* bpf_wq callback — runs on system workqueue, NOT in the target cgroup */
static int wq_callback(void *map, int *key, void *value)
{
	wq_start_ns = bpf_ktime_get_ns();
	bpf_loop(LOOP_ITERS, empty_callback, NULL, 0);
	wq_end_ns = bpf_ktime_get_ns();
	wq_done = 1;
	return 0;
}

/* bpf_thread_wq callback — runs on dedicated kthread IN the target cgroup */
static int twq_callback(void *map, int *key, void *value)
{
	twq_start_ns = bpf_ktime_get_ns();
	bpf_loop(LOOP_ITERS, empty_callback, NULL, 0);
	twq_end_ns = bpf_ktime_get_ns();
	twq_done = 1;
	return 0;
}

SEC("syscall")
__retval(0)
int start_wq(void *ctx)
{
	struct elem *val;
	int key = 0;
	int ret;

	val = bpf_map_lookup_elem(&map_arr, &key);
	if (!val)
		return -1;

	ret = bpf_wq_init(&val->wq, &map_arr, 0);
	if (ret) {
		err_wq = ret;
		return ret;
	}

	ret = bpf_wq_set_callback(&val->wq, wq_callback, 0);
	if (ret) {
		err_wq = ret;
		return ret;
	}

	ret = bpf_wq_start(&val->wq, 0);
	if (ret) {
		err_wq = ret;
		return ret;
	}

	return 0;
}

SEC("syscall")
__retval(0)
int start_thread_wq(void *ctx)
{
	struct elem *val;
	int key = 0;
	int ret;

	val = bpf_map_lookup_elem(&map_arr, &key);
	if (!val)
		return -1;

	ret = bpf_thread_wq_init(&val->twq, &map_arr, target_cgroup_id, 0);
	if (ret) {
		err_twq = ret;
		return ret;
	}

	ret = bpf_thread_wq_set_callback(&val->twq, twq_callback, 0);
	if (ret) {
		err_twq = ret;
		return ret;
	}

	ret = bpf_thread_wq_start(&val->twq, 0);
	if (ret) {
		err_twq = ret;
		return ret;
	}

	return 0;
}
