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
#include <signal.h>
#include <stdbool.h>
#include <getopt.h>
#include <ctype.h>
#include <limits.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#include "afp.skel.h"

static bool exiting;

static void sig_handler(int sig)
{
	exiting = true;
}

static void usage(const char *name)
{
	fprintf(stderr, "Usage: %s --path=<path> --limit=<size>\\\n\n", name);
	fprintf(stderr, "Required arguments:\n");
	fprintf(stderr, "  -p, --path=PATH        Memcgroup path\n");
	fprintf(stderr, "  -l, --limit=SIZE       Limit size\n"
			"                         Plain number (bytes) or suffixed:\n"
			"                         K/KB, M/MB, G/GB, T/TB\n"
			"                         (case-insensitive, e.g. 512m, 1GB)\n");
	fprintf(stderr, "Optional arguments:\n");
	fprintf(stderr, "  -h, --help             Show this help message\n\n");
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
	static const struct option long_opts[] = {
		{ "path",  required_argument, NULL, 'p' },
		{ "limit", required_argument, NULL, 'l' },
		{ "help",  no_argument,       NULL, 'h' },
		{ NULL,    0,                 NULL,  0  }
	};

	uint64_t cgroup_id, limit_bytes;
	char *limit_str = NULL;
	char *path = NULL;
	char hr[32];
	int opt, err;
	struct afp_bpf *skel;

	while ((opt = getopt_long(argc, argv, "p:l:h",
				  long_opts, NULL)) != -1) {
		switch (opt) {
		case 'p':
			path = optarg;
			break;
		case 'l':
			limit_str = optarg;
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

	err = parse_size(limit_str, &limit_bytes);
	if (err)
		return err;
	cgroup_id = get_cgroup_id(path);
	if (!cgroup_id)
		return -EINVAL;

	skel = afp_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return -EINVAL;
	}
	err = afp_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}

	err = afp_bpf__attach(skel);
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

cleanup:
	afp_bpf__destroy(skel);
	return err;
}
