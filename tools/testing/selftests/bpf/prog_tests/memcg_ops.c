// SPDX-License-Identifier: GPL-2.0
/*
 * Memory controller eBPF struct ops test
 */

#include <test_progs.h>
#include <bpf/btf.h>
#include "cgroup_helpers.h"

struct local_config {
	u64 threshold;
	u64 high_cgroup_id;
	unsigned int over_high;
} local_config;

#include "memcg_ops_over_high.skel.h"

#define OVER_HIGH_THRESHOLD 64
#define OVER_HIGH_NUM 512
#define FILE_SIZE (512 * 1024 * 1024ul)
#define BUFFER_SIZE (128 * 1024)
#define READ_ITERATIONS 5
#define CG_LIMIT (512 * 1024 * 1024ul)

#define CG_DIR "/memcg_ops_test"
#define CG_HIGH_DIR CG_DIR "/high"
#define CG_LOW_DIR CG_DIR "/low"


static int setup_cgroup(int *high_cgroup_id, int *low_cgroup_fd)
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
	ret = enable_controllers(CG_DIR, "memory");
	if (!ASSERT_OK(ret, "enable_controllers"))
		goto cleanup;
	snprintf(limit_buf, 20, "%ld", CG_LIMIT);
	ret = write_cgroup_file(CG_DIR, "memory.max", limit_buf);
	if (!ASSERT_OK(ret, "write_cgroup_file"))
		goto cleanup;

	ret = create_and_get_cgroup(CG_HIGH_DIR);
	if (!ASSERT_GE(ret, 0, "create_and_get_cgroup "CG_HIGH_DIR))
		goto cleanup;
	close(ret);
	ret = (int)get_cgroup_id(CG_HIGH_DIR);
	if (!ASSERT_GE(ret, 0, "get_cgroup_id"))
		goto cleanup;
	*high_cgroup_id = ret;

	ret = create_and_get_cgroup(CG_LOW_DIR);
	if (!ASSERT_GE(ret, 0, "create_and_get_cgroup "CG_LOW_DIR))
		goto cleanup;
	*low_cgroup_fd = ret;

	return 0;

cleanup:
	cleanup_cgroup_environment();
	return -1;
}

int write_file(const char *filename)
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

int read_file(const char *filename, int iterations)
{
	int ret = -1;
	char *buffer;

	buffer = malloc(BUFFER_SIZE);
	if (!buffer)
		goto out;

	for (int iter = 0; iter < iterations; iter++) {
		FILE *fp = fopen(filename, "rb");

		if (!fp)
			goto cleanup;

		size_t total_read = 0;
		size_t bytes_read;

		while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, fp)) > 0)
			total_read += bytes_read;

		fclose(fp);

		if (env.verbosity >= VERBOSE_NORMAL)
			printf("%s %d %d done\n",
				__func__, getpid(), iter);
	}

	ret = 0;
cleanup:
	free(buffer);
out:
	return ret;
}

static void real_test_memcg_ops_over_high_child_work(const char *cgroup_path,
						     char *data_filename,
						     char *time_filename)
{
	struct timeval start, end;
	double elapsed;
	FILE *fp;

	if (!ASSERT_OK(join_parent_cgroup(cgroup_path), "join_parent_cgroup"))
		goto out;

	if (env.verbosity >= VERBOSE_NORMAL)
		printf("%s %d begin\n", __func__, getpid());

	gettimeofday(&start, NULL);

	if (!ASSERT_OK(write_file(data_filename), "write_file"))
		goto out;

	if (env.verbosity >= VERBOSE_NORMAL)
		printf("%s %d write_file done\n", __func__, getpid());

	if (!ASSERT_OK(read_file(data_filename, READ_ITERATIONS), "read_file"))
		goto out;

	gettimeofday(&end, NULL);

	elapsed = (end.tv_sec - start.tv_sec) +
		  (end.tv_usec - start.tv_usec) / 1000000.0;

	if (env.verbosity >= VERBOSE_NORMAL)
		printf("%s %d end %.6f\n", __func__, getpid(), elapsed);

	fp = fopen(time_filename, "w");
	if (!ASSERT_OK_PTR(fp, "fopen"))
		goto out;
	fprintf(fp, "%.6f", elapsed);
	fclose(fp);

out:
	exit(0);
}

static int get_time(char *time_filename, double *time)
{
	int ret = -1;
	FILE *fp;

	fp = fopen(time_filename, "r");
	if (!fp)
		goto out;

	if (fscanf(fp, "%lf", time) < 0)
		goto cleanup;

	ret = 0;
cleanup:
	fclose(fp);
out:
	return ret;
}

static void real_test_memcg_ops_over_high(void)
{
	int ret;
	char data_file1[] = "/tmp/test_data_XXXXXX";
	char data_file2[] = "/tmp/test_data_XXXXXX";
	char time_file1[] = "/tmp/test_time_XXXXXX";
	char time_file2[] = "/tmp/test_time_XXXXXX";
	pid_t pid1, pid2;
	double time1, time2;

	ret = mkstemp(data_file1);
	if (!ASSERT_GT(ret, 0, "mkstemp"))
		return;
	close(ret);
	ret = mkstemp(data_file2);
	if (!ASSERT_GT(ret, 0, "mkstemp"))
		goto cleanup_data_file1;
	close(ret);
	ret = mkstemp(time_file1);
	if (!ASSERT_GT(ret, 0, "mkstemp"))
		goto cleanup_data_file2;
	close(ret);
	ret = mkstemp(time_file2);
	if (!ASSERT_GT(ret, 0, "mkstemp"))
		goto cleanup_time_file1;
	close(ret);

	pid1 = fork();
	if (!ASSERT_GE(pid1, 0, "fork"))
		goto cleanup;
	if (pid1 == 0)
		real_test_memcg_ops_over_high_child_work(CG_LOW_DIR,
							 data_file1,
							 time_file1);

	pid2 = fork();
	if (!ASSERT_GE(pid1, 0, "fork"))
		goto cleanup;
	if (pid2 == 0)
		real_test_memcg_ops_over_high_child_work(CG_HIGH_DIR,
							 data_file2,
							 time_file2);

	ret = waitpid(pid1, NULL, 0);
	if (!ASSERT_GT(ret, 0, "waitpid"))
		goto cleanup;

	ret = waitpid(pid2, NULL, 0);
	if (!ASSERT_GT(ret, 0, "waitpid"))
		goto cleanup;

	if (CHECK_FAIL(get_time(time_file1, &time1)))
		goto cleanup;

	if (CHECK_FAIL(get_time(time_file2, &time2)))
		goto cleanup;

	ASSERT_TRUE(time1 > time2 && time1 - time2 > 1,
		    "low fast compare");

cleanup:
	unlink(time_file2);
cleanup_time_file1:
	unlink(time_file1);
cleanup_data_file2:
	unlink(data_file2);
cleanup_data_file1:
	unlink(data_file1);
}

void test_memcg_ops_over_high(void)
{
	int err, map_fd;
	struct memcg_ops_over_high *skel;
	struct bpf_map *map;
	size_t bss_sz;
	struct memcg_ops_over_high__bss *bss_data;
	__u32 key = 0;
	struct bpf_program *prog = NULL;
	struct bpf_link *link = NULL, *link2 = NULL;
	DECLARE_LIBBPF_OPTS(bpf_struct_ops_opts, opts);
	int high_cgroup_id, low_cgroup_fd;

	err = setup_cgroup(&high_cgroup_id, &low_cgroup_fd);
	if (!ASSERT_OK(err, "setup_cgroup"))
		goto out;

	skel = memcg_ops_over_high__open_and_load();
	if (!ASSERT_OK_PTR(skel, "memcg_ops_over_high__open_and_load"))
		goto out;

	map = bpf_object__find_map_by_name(skel->obj, ".bss");
	if (!ASSERT_OK_PTR(map, "bpf_object__find_map_by_name .bss"))
		goto out;

	map_fd = bpf_map__fd(map);
	bss_sz = bpf_map__value_size(map);
	bss_data = malloc(bpf_map__value_size(map));
	if (!ASSERT_OK_PTR(bss_data, "malloc(bpf_map__value_size(map))"))
		goto out;
	memset(bss_data, 0, sizeof(struct local_config));
	bss_data->local_config.high_cgroup_id = high_cgroup_id;
	bss_data->local_config.threshold = OVER_HIGH_THRESHOLD;
	bss_data->local_config.over_high = OVER_HIGH_NUM;
	err = bpf_map_update_elem(map_fd, &key, bss_data, BPF_EXIST);
	free(bss_data);
	if (!ASSERT_OK(err, "bpf_map_update_elem"))
		goto out;

	prog = bpf_object__find_program_by_name(skel->obj,
						"handle_count_memcg_events");
	if (!ASSERT_OK_PTR(prog, "bpf_object__find_program_by_name"))
		goto out;

	link = bpf_program__attach(prog);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach"))
		goto out;

	map = bpf_object__find_map_by_name(skel->obj, "mcg_ops");
	if (!ASSERT_OK_PTR(link, "bpf_object__find_map_by_name mcg_ops"))
		goto out;

	opts.relative_fd = low_cgroup_fd;
	link2 = bpf_map__attach_struct_ops_opts(map, &opts);
	if (!ASSERT_OK_PTR(link, "bpf_map__attach_struct_ops_opts"))
		goto out;

	real_test_memcg_ops_over_high();

out:
	bpf_link__destroy(link);
	bpf_link__destroy(link2);
	memcg_ops_over_high__detach(skel);
	close(low_cgroup_fd);
	cleanup_cgroup_environment();
}
