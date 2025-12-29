// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#ifndef __MEMCG_RSTAT_SIMPLE_BPF_SKEL_H__
#define u64 uint64_t
#endif

struct local_config {
	u64 threshold;
	u64 high_cgroup_id;
	unsigned int over_high;
} local_config;

#include "memcg.skel.h"

static bool exiting;

static void sig_handler(int sig)
{
	exiting = true;
}

static void usage(char *name)
{
	fprintf(stderr,
		"Usage: %s <low_path> <high_path> <threshold> <over_high>\n",
		name);
	fprintf(stderr, "low_path:  low priority memcgroup path.\n");
	fprintf(stderr, "high_path: high priority memcgroup path.\n");
	fprintf(stderr, "threshold: The sum of 'val' PGSCAN of high\n"
			"           priority memcgroup in 1 sec to trigger\n"
			"           low priority cgroup over_high.\n");
	fprintf(stderr, "over_high: low_path over_high value.\n");
}

static uint64_t get_cgroup_id(const char *cgroup_path)
{
	struct stat st;

	if (cgroup_path == NULL) {
		fprintf(stderr, "Error: cgroup_path is NULL\n");
		return 0;
	}

	if (stat(cgroup_path, &st) < 0) {
		fprintf(stderr, "Error: stat(%s) failed: %d\n",
			cgroup_path, errno);
		return 0;
	}

	return (uint64_t)st.st_ino;
}

int main(int argc, char **argv)
{
	int low_cgroup_fd = -1;
	uint64_t threshold, high_cgroup_id;
	unsigned int over_high;
	const char *bpf_obj_file = "memcg.bpf.o";
	struct bpf_object *obj = NULL;
	struct bpf_program *prog = NULL;
	struct bpf_link *link = NULL, *link2 = NULL;
	struct bpf_map *map;
	struct memcg__bss *bss_data;
	DECLARE_LIBBPF_OPTS(bpf_struct_ops_opts, opts);
	int err = -EINVAL;
	int map_fd;

	if (argc < 5) {
usage_err:
		usage(argv[0]);
		goto out;
	}

	low_cgroup_fd = open(argv[1], O_RDONLY);
	if (low_cgroup_fd < 0) {
		fprintf(stderr,
			"ERROR: open low cgroup '%s' failed: %d\n",
			argv[1], errno);
		err = -errno;
		goto out;
	}

	high_cgroup_id = get_cgroup_id(argv[2]);
	if (!high_cgroup_id)
		goto out;

	threshold = strtoull(argv[3], NULL, 10);
	over_high = strtoull(argv[4], NULL, 10);
	if (!threshold || !over_high)
		goto usage_err;

	obj = bpf_object__open_file(bpf_obj_file, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr,
			"ERROR: opening BPF object file '%s' failed: %d\n",
			bpf_obj_file, err);
		goto out;
	}

	map = bpf_object__find_map_by_name(obj, ".bss");
	if (!map) {
		fprintf(stderr, "ERROR: Failed to find .data map\n");
		err = -ESRCH;
		goto out;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr,
			"ERROR: loading BPF object file failed: %d\n",
			err);
		goto out;
	}

	map_fd = bpf_map__fd(map);
	bss_data = malloc(bpf_map__value_size(map));
	if (bss_data) {
		__u32 key = 0;

		memset(bss_data, 0, sizeof(struct local_config));
		bss_data->local_config.high_cgroup_id = high_cgroup_id;
		bss_data->local_config.threshold = threshold;
		bss_data->local_config.over_high = over_high;

		err = bpf_map_update_elem(map_fd, &key, bss_data, BPF_EXIST);
		free(bss_data);
		if (err) {
			fprintf(stderr,
				"ERROR: update config failed: %d\n",
				err);
			goto out;
		}
	} else {
		fprintf(stderr,
			"ERROR: allocate memory failed\n");
		err = -ENOMEM;
		goto out;
	}

	prog = bpf_object__find_program_by_name(obj,
						"handle_count_memcg_events");
	if (!prog) {
		fprintf(stderr,
			"ERROR: finding a prog in BPF object file failed\n");
		goto out;
	}

	link = bpf_program__attach(prog);
	err = libbpf_get_error(link);
	if (err) {
		fprintf(stderr,
			"ERROR: bpf_program__attach failed: %d\n",
			err);
		goto out;
	}

	map = bpf_object__find_map_by_name(obj, "mcg_ops");
	if (!map) {
		fprintf(stderr, "ERROR: Failed to find mcg_ops map\n");
		err = -ESRCH;
		goto out;
	}

	opts.relative_fd = low_cgroup_fd;
	link2 = bpf_map__attach_struct_ops_opts(map, &opts);
	if (!link2) {
		fprintf(stderr,
			"Failed to attach struct ops mcg_ops: %d\n", errno);
		err = -errno;
		goto out;
	}

	printf("Successfully attached!\n");

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (!exiting)
		pause();

	printf("Exiting...\n");

out:
	bpf_link__destroy(link);
	bpf_link__destroy(link2);
	bpf_object__close(obj);
	close(low_cgroup_fd);
	return err;
}
