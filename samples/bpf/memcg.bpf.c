// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ONE_SECOND_NS	1000000000

struct local_config {
	u64 threshold;
	u64 high_cgroup_id;
	unsigned int over_high;
} local_config;

struct AggregationData {
	u64 sum;
	u64 window_start_ts;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct AggregationData);
} aggregation_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} trigger_ts_map SEC(".maps");

SEC("tp/memcg/count_memcg_events")
int
handle_count_memcg_events(struct trace_event_raw_memcg_rstat_events *ctx)
{
	u32 key = 0;
	struct AggregationData *data;
	u64 current_ts;

	if (ctx->id != local_config.high_cgroup_id ||
	    (ctx->item != PGSCAN_KSWAPD && ctx->item != PGSCAN_DIRECT))
		goto out;

	data = bpf_map_lookup_elem(&aggregation_map, &key);
	if (!data)
		goto out;

	current_ts = bpf_ktime_get_ns();

	if (current_ts - data->window_start_ts < ONE_SECOND_NS) {
		data->sum += ctx->val;
	} else {
		data->window_start_ts = current_ts;
		data->sum = ctx->val;
	}

	if (data->sum > local_config.threshold) {
		bpf_map_update_elem(&trigger_ts_map, &key, &current_ts,
				    BPF_ANY);
		data->sum = 0;
		data->window_start_ts = current_ts;
	}

out:
	return 0;
}

SEC("struct_ops/memcg_nr_pages_over_high")
unsigned int memcg_nr_pages_over_high_impl(struct mem_cgroup *memcg)
{
	u32 key = 0;
	u64 *trigger_ts;
	unsigned int ret = 0;

	trigger_ts = bpf_map_lookup_elem(&trigger_ts_map, &key);
	if (!trigger_ts || *trigger_ts == 0)
		goto out;

	u64 current_ts = bpf_ktime_get_ns();

	if (current_ts - *trigger_ts < ONE_SECOND_NS)
		ret = local_config.over_high;

out:
	return ret;
}

SEC(".struct_ops.link")
struct memcg_bpf_ops mcg_ops = {
	.memcg_nr_pages_over_high = (void *)memcg_nr_pages_over_high_impl,
};

char LICENSE[] SEC("license") = "GPL";
