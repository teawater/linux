// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 */

#include "bpf_experimental.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct elem {
	struct bpf_thread_wq twq;
};

struct hmap_elem {
	int counter;
	struct bpf_thread_wq twq;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, struct elem);
} array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000);
	__type(key, int);
	__type(value, struct hmap_elem);
} hmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4);
	__type(key, int);
	__type(value, struct elem);
} lru SEC(".maps");

__u32 ok;

static int twq_callback(void *map, int *key, void *value)
{
	ok |= (1 << *key);
	return 0;
}

SEC("syscall")
__retval(0)
long test_thread_wq_array(void *ctx)
{
	struct bpf_thread_wq *twq;
	struct elem *val;
	int key = 0;

	val = bpf_map_lookup_elem(&array, &key);
	if (!val)
		return -1;

	twq = &val->twq;
	if (bpf_thread_wq_init(twq, &array, 0, 0) != 0)
		return -2;

	if (bpf_thread_wq_set_callback(twq, twq_callback, 0))
		return -3;

	if (bpf_thread_wq_start(twq, 0))
		return -4;

	return 0;
}

SEC("syscall")
__retval(0)
long test_thread_wq_hash(void *ctx)
{
	struct bpf_thread_wq *twq;
	struct hmap_elem init = {}, *val;
	int key = 1;

	if (bpf_map_update_elem(&hmap, &key, &init, 0))
		return -1;

	val = bpf_map_lookup_elem(&hmap, &key);
	if (!val)
		return -2;

	twq = &val->twq;
	if (bpf_thread_wq_init(twq, &hmap, 0, 0) != 0)
		return -3;

	if (bpf_thread_wq_set_callback(twq, twq_callback, 0))
		return -4;

	if (bpf_thread_wq_start(twq, 0))
		return -5;

	return 0;
}

SEC("syscall")
__retval(0)
long test_thread_wq_lru(void *ctx)
{
	struct bpf_thread_wq *twq;
	struct elem init = {}, *val;
	int key = 2;

	if (bpf_map_update_elem(&lru, &key, &init, 0))
		return -1;

	val = bpf_map_lookup_elem(&lru, &key);
	if (!val)
		return -2;

	twq = &val->twq;
	if (bpf_thread_wq_init(twq, &lru, 0, 0) != 0)
		return -3;

	if (bpf_thread_wq_set_callback(twq, twq_callback, 0))
		return -4;

	if (bpf_thread_wq_start(twq, 0))
		return -5;

	return 0;
}
