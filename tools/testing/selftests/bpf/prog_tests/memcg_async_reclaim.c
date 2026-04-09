// SPDX-License-Identifier: GPL-2.0
/*
 * Memory controller eBPF async reclaim test
 */

#include <test_progs.h>
#include <bpf/btf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "cgroup_helpers.h"

struct bpf_args_s {
	u64 cgroup_id;
	u64 limit_bytes;
};

#include "memcg_async_reclaim.skel.h"

#define FILE_SIZE (64 * 1024 * 1024ul)
#define BUFFER_SIZE (4096)
#define CG_LIMIT (32 * 1024 * 1024ul)
#define CG_DIR "/memcg_async_reclaim"
#define RECLAIM_TRIGGER_SIZE (16 * 1024 * 1024ul)

static int
setup_cgroup(u64 cg_max, u64 *cgroup_id)
{
	int ret;
	char limit_buf[20];

	ret = setup_cgroup_environment();
	if (!ASSERT_OK(ret, "setup_cgroup_environment"))
		goto cleanup;

	ret = create_and_get_cgroup(CG_DIR);
	if (!ASSERT_GE(ret, 0, "create_and_get_cgroup "CG_DIR))
		goto cleanup;
	close(ret);

	*cgroup_id = get_cgroup_id(CG_DIR);
	if (!ASSERT_GT(*cgroup_id, 0, "get_cgroup_id"))
		goto cleanup;

	snprintf(limit_buf, 20, "%lu", cg_max);
	ret = write_cgroup_file(CG_DIR, "memory.max", limit_buf);
	if (!ASSERT_OK(ret, "write_cgroup_file memory.max"))
		goto cleanup;

	ret = write_cgroup_file(CG_DIR, "memory.swap.max", "0");
	if (!ASSERT_OK(ret, "write_cgroup_file memory.swap.max"))
		goto cleanup;

	return 0;

cleanup:
	cleanup_cgroup_environment();
	return -1;
}

int setup_bpf(u64 cg_id, u64 limit_bytes,
	      struct memcg_async_reclaim **skel_ptr)
{
	int err;
	struct memcg_async_reclaim *skel;
	struct bpf_args_s bpf_args = {
		.limit_bytes = limit_bytes,
		.cgroup_id = cg_id,
	};
	LIBBPF_OPTS(bpf_test_run_opts, run_opts,
		.ctx_in = &bpf_args,
		.ctx_size_in = sizeof(bpf_args)
	);
	int prog_init_fd;

	skel = memcg_async_reclaim__open_and_load();
	if (!ASSERT_OK_PTR(skel, "memcg_async_reclaim__open_and_load"))
		return -EINVAL;

	prog_init_fd = bpf_program__fd(skel->progs.prog_init);
	if (!ASSERT_GE(prog_init_fd, 0, "bpf_program__fd")) {
		err = -errno;
		goto error_out;
	}
	err = bpf_prog_test_run_opts(prog_init_fd, &run_opts);
	if (!ASSERT_OK((err || run_opts.retval), "bpf_prog_test_run_opts"))
		goto error_out;

	if (!ASSERT_OK(memcg_async_reclaim__attach(skel),
		       "memcg_async_reclaim__attach"))
		goto error_out;

	*skel_ptr = skel;
	return 0;

error_out:
	memcg_async_reclaim__destroy(skel);
	return err;
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
	char *p;
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

	for (int iter = 0; iter < iterations; iter++) {
		for (i = 0; i < FILE_SIZE; i += page_size) {
			/* access a byte to trigger page fault */
			p = &map[i];
			__asm__ __volatile__("" : : "r"(p) : "memory");
		}

		if (env.verbosity >= VERBOSE_NORMAL)
			printf("%s %d %d done\n", __func__, getpid(), iter);
	}

	if (munmap(map, FILE_SIZE) == -1)
		goto cleanup_fd;

	ret = 0;

cleanup_fd:
	close(fd);
out:
	return ret;
}

int get_cgroup_memory_event(const char *relative_path, const char *key,
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

	ret = read_cgroup_file(relative_path, "memory.events", buf, sizeof(buf));
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

void test_memcg_async_reclaim(void)
{
	u64 cgroup_id, old_max, new_max;
	int ret;
	struct memcg_async_reclaim *skel;
	char data_file1[] = "/tmp/test_data_XXXXXX";
	char data_file2[] = "/tmp/test_data_XXXXXX";

	if (!ASSERT_OK(setup_cgroup(CG_LIMIT, &cgroup_id), "setup_cgroup"))
		return;

	if (!ASSERT_OK(join_cgroup(CG_DIR), "join_cgroup"))
		goto cleanup_cgroup;

	ret = mkstemp(data_file1);
	if (!ASSERT_GE(ret, 0, "mkstemp"))
		return;
	close(ret);
	ret = mkstemp(data_file2);
	if (!ASSERT_GE(ret, 0, "mkstemp"))
		goto cleanup_data_file1;
	close(ret);

	// test without async_reclaim
	if (!ASSERT_OK(get_cgroup_memory_event(CG_DIR, "max", &old_max),
					       "get_cgroup_memory_event"))
		goto cleanup_data_file2;
	if (!ASSERT_OK(write_file(data_file1), "write_file"))
		goto cleanup_data_file2;
	if (!ASSERT_OK(read_file(data_file1, 2), "read_file"))
		goto cleanup_data_file2;
	if (!ASSERT_OK(get_cgroup_memory_event(CG_DIR, "max", &new_max),
					       "get_cgroup_memory_event"))
		goto cleanup_data_file2;
	if (!ASSERT_GT(new_max, old_max, "memcg max event not trigger"))
		goto cleanup_data_file2;

	// test with async_reclaim
	if (!ASSERT_OK(setup_bpf(cgroup_id, RECLAIM_TRIGGER_SIZE, &skel),
		       "setup_bpf"))
		goto cleanup_data_file2;
	if (!ASSERT_OK(get_cgroup_memory_event(CG_DIR, "max", &old_max),
					       "get_cgroup_memory_event"))
		goto cleanup;
	if (!ASSERT_OK(write_file(data_file1), "write_file"))
		goto cleanup;
	if (!ASSERT_OK(read_file(data_file1, 2), "read_file"))
		goto cleanup;
	if (!ASSERT_OK(get_cgroup_memory_event(CG_DIR, "max", &new_max),
					       "get_cgroup_memory_event"))
		goto cleanup;
	if (!ASSERT_EQ(new_max, old_max, "memcg max event triggered"))
		goto cleanup;

cleanup:
	memcg_async_reclaim__detach(skel);
	memcg_async_reclaim__destroy(skel);
cleanup_data_file2:
	unlink(data_file2);
cleanup_data_file1:
	unlink(data_file1);
cleanup_cgroup:
	cleanup_cgroup_environment();
}
