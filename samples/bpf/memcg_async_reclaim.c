// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <getopt.h>
#include <ctype.h>
#include <limits.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#ifndef __MEMCG_ASYNC_RECLAIM_SKEL_H__
#define u64 uint64_t
#define u32 uint32_t
#define s32 int32_t
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* Flags for bpf_args_s.flags */
#define MEMCG_RECLAIM_MAY_SWAP  (1 << 1)
#define MEMCG_RECLAIM_PROACTIVE (1 << 2)

#define MIN_SWAPPINESS 0
#define MAX_SWAPPINESS 200
#define SWAPPINESS_ANON_ONLY (MAX_SWAPPINESS + 1)
#define SWAPPINESS_UNSET (-1)

struct bpf_args_s {
	u64 cgroup_id;
	u64 limit_bytes;
	u32 flags;
	s32 swappiness;
};

#include "memcg_async_reclaim.skel.h"

static bool exiting;

static void sig_handler(int sig)
{
	exiting = true;
}

static void usage(const char *name)
{
	fprintf(stderr,
		"Usage: %s --path=<path> --limit=<size> [options]\n\n",
		name);
	fprintf(stderr, "Required arguments:\n");
	fprintf(stderr,
		"  -p, --path=PATH        Memcgroup path\n");
	fprintf(stderr,
		"  -l, --limit=SIZE       Limit size\n"
		"                         Plain number\n"
		"                         (bytes) or suffixed:\n"
		"                         K/KB, M/MB, G/GB, T/TB\n"
		"                         (case-insensitive,\n"
		"                         e.g. 512m, 1GB)\n");
	fprintf(stderr, "Optional arguments:\n");
	fprintf(stderr,
		"  -P, --proactive        Enable MEMCG_RECLAIM_PROACTIVE\n");
	fprintf(stderr,
		"  -s, --may-swap         Enable MEMCG_RECLAIM_MAY_SWAP\n");
	fprintf(stderr,
		"  -w, --swappiness=N     Swappiness value [%d, %d]\n"
		"                         (default: not set)\n",
		MIN_SWAPPINESS, SWAPPINESS_ANON_ONLY);
	fprintf(stderr,
		"  -h, --help             Show this help message\n\n");
}

/**
 * parse_size - parse a human-readable size string into bytes
 * @str: input string, e.g. "512", "1GB", "256m"
 * @out: pointer to store the resulting byte count
 *
 * Supported suffixes (case-insensitive):
 *   none -> bytes
 *   K/KB -> KiB (x 1024)
 *   M/MB -> MiB (x 1024^2)
 *   G/GB -> GiB (x 1024^3)
 *   T/TB -> TiB (x 1024^4)
 *
 * Return: 0 on success, -1 on failure.
 */
static int parse_size(const char *str, uint64_t *out)
{
	static const struct {
		const char	*suffix;
		uint64_t	multiplier;
	} units[] = {
		{ "TB", 1024ULL * 1024 * 1024 * 1024 },
		{ "GB", 1024ULL * 1024 * 1024        },
		{ "MB", 1024ULL * 1024               },
		{ "KB", 1024ULL                      },
		{ "T",  1024ULL * 1024 * 1024 * 1024 },
		{ "G",  1024ULL * 1024 * 1024        },
		{ "M",  1024ULL * 1024               },
		{ "K",  1024ULL                      },
	};

	uint64_t value;
	uint64_t multiplier = 1ULL;
	char unit[4] = { 0 };
	char *end;
	int i, ui;

	if (!str || !*str) {
		fprintf(stderr, "Error: empty size string.\n");
		return -EINVAL;
	}

	errno = 0;
	value = strtoull(str, &end, 10);
	if (errno != 0 || end == str) {
		fprintf(stderr, "Error: invalid size value '%s'.\n", str);
		return -EINVAL;
	}

	/* Skip optional whitespace between number and unit */
	while (*end == ' ')
		end++;

	/* Normalise the unit to uppercase for comparison */
	for (ui = 0; ui < 3 && end[ui]; ui++)
		unit[ui] = (char)toupper((unsigned char)end[ui]);
	unit[ui] = '\0';

	if (unit[0] == '\0') {
		/* No suffix: treat as raw bytes */
		multiplier = 1ULL;
	} else {
		for (i = 0; i < ARRAY_SIZE(units); i++) {
			if (strcmp(unit, units[i].suffix) == 0) {
				multiplier = units[i].multiplier;
				goto found;
			}
		}

		fprintf(stderr, "Error: unknown size unit '%s'.\n", end);
		return -EINVAL;
	}

found:
	/* Guard against multiplication overflow */
	if (value > ULLONG_MAX / multiplier) {
		fprintf(stderr, "Error: size '%s' overflows.\n", str);
		return -EINVAL;
	}

	*out = value * multiplier;
	return 0;
}

/**
 * parse_swappiness - parse and validate a swappiness value
 * @str: input string, e.g. "60"
 * @out: pointer to store the resulting value
 *
 * Valid range: [SWAPPINESS_MIN, SWAPPINESS_MAX]
 *
 * Return: 0 on success, -EINVAL on failure.
 */
static int parse_swappiness(const char *str, int32_t *out)
{
	long value;
	char *end;

	if (!str || !*str) {
		fprintf(stderr, "Error: empty swappiness string.\n");
		return -EINVAL;
	}

	errno = 0;
	value = strtol(str, &end, 10);
	if (errno != 0 || end == str || *end != '\0') {
		fprintf(stderr, "Error: invalid swappiness value '%s'.\n", str);
		return -EINVAL;
	}

	if (value < MIN_SWAPPINESS || value > SWAPPINESS_ANON_ONLY) {
		fprintf(stderr,
			"Error: swappiness %ld is out of range [%d, %d].\n",
			value, MIN_SWAPPINESS, SWAPPINESS_ANON_ONLY);
		return -EINVAL;
	}

	*out = (int32_t)value;
	return 0;
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

/**
 * Check if a cgroup directory is a leaf node.
 * A leaf node has no child cgroup subdirectories.
 *
 * @param cgroup_path  path to the cgroup directory
 * @return  true  = leaf node
 *          false = internal node (has children), or invalid path
 */
static bool cgroup_is_leaf(const char *cgroup_path)
{
	struct dirent *entry;
	DIR *dir = opendir(cgroup_path);

	if (!dir)
		return false;

	while ((entry = readdir(dir)) != NULL) {
		/* skip . and .. */
		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0)
			continue;

		/* use d_type when available to avoid extra stat call */
		if (entry->d_type == DT_DIR) {
			closedir(dir);
			return false;
		}

		/* fall back to stat if d_type is not supported */
		if (entry->d_type == DT_UNKNOWN) {
			char child_path[PATH_MAX];
			struct stat st;

			snprintf(child_path, sizeof(child_path), "%s/%s",
				 cgroup_path, entry->d_name);

			if (stat(child_path, &st) == 0 && S_ISDIR(st.st_mode)) {
				closedir(dir);
				return false;
			}
		}
	}

	closedir(dir);
	return true;
}

int main(int argc, char **argv)
{
	static const struct option long_opts[] = {
		{ "path",       required_argument, NULL, 'p' },
		{ "limit",      required_argument, NULL, 'l' },
		{ "proactive",  no_argument,       NULL, 'P' },
		{ "may-swap",   no_argument,       NULL, 's' },
		{ "swappiness", required_argument, NULL, 'w' },
		{ "help",       no_argument,       NULL, 'h' },
		{ NULL,         0,                 NULL,  0  }
	};

	char *limit_str = NULL;
	char *path = NULL;
	int opt, err;
	struct bpf_args_s bpf_args = {
		.flags      = 0,
		.swappiness = SWAPPINESS_UNSET,
	};
	struct memcg_async_reclaim *skel;
	int prog_init_fd;

	LIBBPF_OPTS(bpf_test_run_opts, run_opts);

	while ((opt = getopt_long(argc, argv, "p:l:Psw:h",
				  long_opts, NULL)) != -1) {
		switch (opt) {
		case 'p':
			path = optarg;
			break;
		case 'l':
			limit_str = optarg;
			break;
		case 'P':
			bpf_args.flags |= MEMCG_RECLAIM_PROACTIVE;
			break;
		case 's':
			bpf_args.flags |= MEMCG_RECLAIM_MAY_SWAP;
			break;
		case 'w':
			err = parse_swappiness(optarg, &bpf_args.swappiness);
			if (err)
				return err;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return -EINVAL;
		}
	}

	if (!path || !limit_str) {
		fprintf(stderr, "Error: --path and --limit are required.\n\n");
		usage(argv[0]);
		return -EINVAL;
	}

	if (!cgroup_is_leaf(path)) {
		fprintf(stderr, "Error: path %s is not leaf node.\n\n", path);
		return -EINVAL;
	}

	err = parse_size(limit_str, &bpf_args.limit_bytes);
	if (err)
		return err;

	bpf_args.cgroup_id = get_cgroup_id(path);
	if (!bpf_args.cgroup_id)
		return -EINVAL;

	LIBBPF_OPTS_RESET(run_opts,
		.ctx_in      = &bpf_args,
		.ctx_size_in = sizeof(bpf_args)
	);

	skel = memcg_async_reclaim__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return -EINVAL;
	}

	prog_init_fd = bpf_program__fd(skel->progs.prog_init);
	if (prog_init_fd < 0) {
		fprintf(stderr, "Failed to get prog_init fd\n");
		err = -errno;
		goto cleanup;
	}
	err = bpf_prog_test_run_opts(prog_init_fd, &run_opts);
	if (err || run_opts.retval) {
		fprintf(stderr, "BPF_PROG_RUN (init) failed: %d (retval=%d)\n",
			err, run_opts.retval);
		goto cleanup;
	}

	err = memcg_async_reclaim__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	printf("Successfully attached!\n");

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (!exiting)
		pause();

	printf("Exiting...\n");

	memcg_async_reclaim__detach(skel);
cleanup:
	memcg_async_reclaim__destroy(skel);
	return err;
}
