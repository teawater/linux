// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct wq_elem {
	struct bpf_wq work;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u32);
	__type(value, struct wq_elem);
} wq_map SEC(".maps");

struct wq_state {
	__u64 counter;
	__u64 last_run_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct wq_state);
} state_map SEC(".maps");

static volatile __u64 initialized = 0;

static int wq_cb(void *map, int *key, void *value)
{
	__u32 k = 0;
	struct wq_state *s = bpf_map_lookup_elem(&state_map, &k);
	if (!s)
		return 0;

	s->counter++;
	s->last_run_ns = bpf_ktime_get_ns();
	bpf_printk("wq fired: counter=%llu\n", s->counter);
	return 0;
}

SEC("syscall")
int prog_init(void *ctx)
{
	__u32 key = 0;
	struct wq_elem *elem;
	int ret;

	if (__sync_fetch_and_add(&initialized, 0) != 0)
		return 1;

	elem = bpf_map_lookup_elem(&wq_map, &key);
	if (!elem)
		return -1;

	struct bpf_wq *wq = &elem->work;

	ret = bpf_wq_init(wq, &wq_map, 0);
	if (ret)
		return ret;

	ret = bpf_wq_set_callback(wq, wq_cb, 0);
	if (ret)
		return ret;

	__sync_fetch_and_add(&initialized, 1);
	return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int on_openat(struct trace_event_raw_sys_enter *ctx)
{
	if (!__sync_fetch_and_add(&initialized, 0))
		return 0;

	__u32 key = 0;
	struct wq_elem *elem = bpf_map_lookup_elem(&wq_map, &key);
	if (!elem)
		return 0;

	bpf_wq_start(&elem->work, 0);
	return 0;
}
