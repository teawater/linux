// SPDX-License-Identifier: GPL-2.0
/*
 * Memory controller eBPF async reclaim test
 */

#include <test_progs.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "cgroup_helpers.h"

struct bpf_args_s {
	u64 cgroup_id;
	u64 event_delta_threshold;
	u64 check_ns;
};

#include "memcg_async_reclaim.skel.h"

#define BUFFER_SIZE (4096)
#define CG_LIMIT (32 * 1024 * 1024ul)
#define FILE_SIZE (40 * 1024 * 1024ul)
#define READ_TIMES 3

#define CG_DIR1 "/memcg_async_reclaim1"
#define CG_DIR2 "/memcg_async_reclaim2"
#define CG_DIR3 "/memcg_async_reclaim3"

#define CHECK_PERIOD_NS (2 * 1000 * 1000ull)
#define EVENT_DELTA_THRESHOLD 1

static int
setup_max_cgroup(const char *cg_path, u64 cg_max, u64 *cgroup_id)
{
	int ret;
	char limit_buf[20];

	ret = create_and_get_cgroup(cg_path);
	if (!ASSERT_GE(ret, 0, "create_and_get_cgroup"))
		goto out;
	close(ret);

	*cgroup_id = get_cgroup_id(cg_path);
	if (!ASSERT_GT(*cgroup_id, 0, "get_cgroup_id")) {
		ret = -EINVAL;
		goto out;
	}

	snprintf(limit_buf, sizeof(limit_buf), "%lu", cg_max);
	ret = write_cgroup_file(cg_path, "memory.max", limit_buf);
	if (!ASSERT_OK(ret, "write_cgroup_file memory.max"))
		goto out;

	ret = write_cgroup_file(cg_path, "memory.swap.max", "0");
	if (!ASSERT_OK(ret, "write_cgroup_file memory.swap.max"))
		goto out;

out:
	return ret;
}

static int
setup_bpf(struct memcg_async_reclaim *skel, u64 cg_id, bool is_bpf_thread_wq)
{
	struct bpf_args_s bpf_args = {
		.cgroup_id = cg_id,
		.event_delta_threshold = EVENT_DELTA_THRESHOLD,
		.check_ns = CHECK_PERIOD_NS,
	};
	LIBBPF_OPTS(bpf_test_run_opts, run_opts,
		.ctx_in = &bpf_args,
		.ctx_size_in = sizeof(bpf_args));
	int prog_fd, err;

	if (is_bpf_thread_wq)
		prog_fd = bpf_program__fd(skel->progs.thread_wq_prog_init);
	else
		prog_fd = bpf_program__fd(skel->progs.wq_prog_init);
	if (!ASSERT_GE(prog_fd, 0, "bpf_program__fd"))
		return -1;

	err = bpf_prog_test_run_opts(prog_fd, &run_opts);
	if (!ASSERT_OK(err, "bpf_prog_test_run_opts"))
		return -1;
	if (!ASSERT_EQ(run_opts.retval, 0, "prog_init retval"))
		return -1;

	return 0;
}

static int write_file(const char *filename)
{
	int ret = -1;
	size_t written = 0;
	char *buffer;
	FILE *fp;

	fp = fopen(filename, "wb");
	if (!fp)
		goto out;

	buffer = malloc(BUFFER_SIZE);
	if (!buffer)
		goto cleanup_fp;

	memset(buffer, 'A', BUFFER_SIZE);

	while (written < FILE_SIZE) {
		size_t to_write = (FILE_SIZE - written < BUFFER_SIZE) ?
				   (FILE_SIZE - written) :
				   BUFFER_SIZE;

		if (fwrite(buffer, 1, to_write, fp) != to_write)
			goto cleanup;
		written += to_write;
	}

	ret = 0;
cleanup:
	free(buffer);
cleanup_fp:
	fclose(fp);
out:
	return ret;
}

static int read_file(const char *filename, int iterations)
{
	int ret = -1;
	long page_size = sysconf(_SC_PAGESIZE);
	char *map;
	size_t i;
	int fd;
	struct stat sb;

	fd = open(filename, O_RDONLY);
	if (fd == -1)
		goto out;

	if (fstat(fd, &sb) == -1)
		goto cleanup_fd;

	if (sb.st_size != FILE_SIZE) {
		fprintf(stderr, "File size mismatch: expected %lu, got %lu\n",
			(unsigned long)FILE_SIZE, (unsigned long)sb.st_size);
		goto cleanup_fd;
	}

	map = mmap(NULL, FILE_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED)
		goto cleanup_fd;

	/*
	 * Disable readahead so each access after eviction is a real
	 * (potentially major) fault instead of being masked by
	 * sequential prefetch.
	 */
	if (madvise(map, FILE_SIZE, MADV_RANDOM))
		fprintf(stderr, "madvise(MADV_RANDOM) failed: %s\n",
			strerror(errno));

	for (int iter = 0; iter < iterations; iter++) {
		for (i = 0; i < FILE_SIZE; i += page_size) {
			/* access a byte to trigger page fault */
			volatile char v = map[i];
			(void)v;
		}
	}

	if (munmap(map, FILE_SIZE) == -1)
		goto cleanup_fd;

	ret = 0;

cleanup_fd:
	close(fd);
out:
	return ret;
}

static int get_cgroup_memory_event(const char *relative_path, const char *key,
				   u64 *value)
{
	char buf[1024];
	char *line, *saveptr1;
	char *c, *saveptr2;
	char *val_str = NULL;
	bool found = false;
	int ret, i;

	if (!key || !value)
		return -EINVAL;

	ret = read_cgroup_file(relative_path, "memory.events",
			       buf, sizeof(buf));
	if (ret < 0)
		return ret;

	for (line = strtok_r(buf, "\n", &saveptr1); line;
	     line = strtok_r(NULL, "\n", &saveptr1)) {
		val_str = NULL;
		i = 0;

		for (c = strtok_r(line, " ", &saveptr2); c;
		     c = strtok_r(NULL, " ", &saveptr2)) {
			if (i == 0) {
				if (strcmp(c, key) != 0)
					break;
			} else if (i == 1) {
				val_str = c;
				break;
			}
			i++;
		}

		if (val_str) {
			char *endptr;
			u64 v;

			v = strtoull(val_str, &endptr, 10);
			if (endptr == val_str)
				return -EINVAL;

			*value = v;
			found = true;
			break;
		}
	}

	if (!found)
		return -ENOENT;

	return 0;
}

/*
 * Runs the write+read workload inside cg_path and returns the number of
 * new memory.events "max" events (memory.max limit hits) it caused.
 */
static int run_workload(const char *cg_path, u64 *max_delta)
{
	char data_file[] = "/tmp/memcg_async_reclaim_data_XXXXXX";
	u64 old_max, new_max;
	int ret;

	if (!ASSERT_OK(join_cgroup(cg_path), "join_cgroup"))
		return -1;

	ret = mkstemp(data_file);
	if (!ASSERT_GE(ret, 0, "mkstemp"))
		return -1;
	close(ret);

	if (!ASSERT_OK(get_cgroup_memory_event(cg_path, "max", &old_max),
					       "get_cgroup_memory_event"))
		goto cleanup;

	if (!ASSERT_OK(write_file(data_file), "write_file"))
		goto cleanup;
	if (!ASSERT_OK(read_file(data_file, READ_TIMES), "read_file"))
		goto cleanup;

	if (!ASSERT_OK(get_cgroup_memory_event(cg_path, "max", &new_max),
					       "get_cgroup_memory_event"))
		goto cleanup;

	if (!ASSERT_GE(new_max, old_max, "memcg max event went backwards"))
		goto cleanup;

	*max_delta = new_max - old_max;

	ret = 0;

cleanup:
	unlink(data_file);
	return ret;
}

void test_memcg_async_reclaim(void)
{
	u64 cgroup_id, max_change1 = 0, max_change2 = 0, max_change3 = 0;
	struct memcg_async_reclaim *skel = NULL;

	if (!ASSERT_OK(setup_cgroup_environment(), "setup_cgroup_environment"))
		return;

	/* Baseline: no BPF async reclaim attached. */
	if (!ASSERT_OK(setup_max_cgroup(CG_DIR1, CG_LIMIT, &cgroup_id),
		       "setup_max_cgroup"))
		goto cleanup_cgroup;
	if (run_workload(CG_DIR1, &max_change1))
		goto cleanup_cgroup;
	if (!ASSERT_GT(max_change1, 0, "memcg max event not triggered"))
		goto cleanup_cgroup;

	skel = memcg_async_reclaim__open_and_load();
	if (!ASSERT_OK_PTR(skel, "memcg_async_reclaim__open_and_load"))
		goto cleanup_cgroup;

	/* bpf_wq based async reclaim. */
	if (!ASSERT_OK(setup_max_cgroup(CG_DIR2, CG_LIMIT, &cgroup_id),
		       "setup_max_cgroup"))
		goto cleanup_skel;
	if (setup_bpf(skel, cgroup_id, false))
		goto cleanup_skel;
	if (run_workload(CG_DIR2, &max_change2))
		goto cleanup_skel;

	/* bpf_thread_wq based async reclaim. */
	if (!ASSERT_OK(setup_max_cgroup(CG_DIR3, CG_LIMIT, &cgroup_id),
		       "setup_max_cgroup"))
		goto cleanup_skel;
	if (setup_bpf(skel, cgroup_id, true))
		goto cleanup_skel;
	if (run_workload(CG_DIR3, &max_change3))
		goto cleanup_skel;

	ASSERT_LT(max_change2, max_change1,
		 "bpf_wq async reclaim did not reduce memcg max events");
	ASSERT_LT(max_change3, max_change1,
		 "bpf_thread_wq async reclaim did not reduce memcg max events");

	printf("%lu %lu %lu", max_change1, max_change2, max_change3);

cleanup_skel:
	if (skel)
		memcg_async_reclaim__destroy(skel);
cleanup_cgroup:
	/*
	 * Wait for bpf_thread_wq to release the reference to cgroup
	 * to ensure the successful deletion of cgroup.
	 */
	//sleep(1);
	//cleanup_cgroup_environment();
}
