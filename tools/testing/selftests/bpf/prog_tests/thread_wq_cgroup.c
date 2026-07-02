// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "cgroup_helpers.h"
#include "thread_wq_cgroup.skel.h"

#define TEST_CGROUP "/thread_wq_test"
#define CPU_MAX_THROTTLED "1000 100000"  /* 1% of CPU bandwidth */
#define WAIT_TIMEOUT_SECS 30

void test_thread_wq_cgroup(void)
{
	struct thread_wq_cgroup *skel = NULL;
	int err, prog_fd, cg_fd = -1;
	unsigned long long cg_id;
	int waited_secs;
	__u64 old_duration, new_duration;
	LIBBPF_OPTS(bpf_test_run_opts, topts);

	err = setup_cgroup_environment();
	if (!ASSERT_OK(err, "setup_cgroup_environment"))
		return;
	cg_fd = create_and_get_cgroup(TEST_CGROUP);
	if (!ASSERT_GE(cg_fd, 0, "create_and_get_cgroup"))
		goto cleanup;
	cg_id = get_cgroup_id(TEST_CGROUP);
	if (!ASSERT_GT(cg_id, (unsigned long long)0, "get_cgroup_id"))
		goto cleanup;

	skel = thread_wq_cgroup__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto cleanup;
	skel->bss->target_cgroup_id = cg_id;

	prog_fd = bpf_program__fd(skel->progs.start_thread_wq);

	/* Test without cpu limit. */
	if (!ASSERT_OK((bpf_prog_test_run_opts(prog_fd, &topts) ||
			topts.retval),
			"bpf_prog_test_run_opts without limit"))
		goto cleanup;
	for (waited_secs = 0; waited_secs < WAIT_TIMEOUT_SECS; waited_secs++) {
		if (skel->bss->twq_done)
			break;
		sleep(1);
	}
	if (!ASSERT_TRUE(skel->bss->twq_done, "twq_done without limit"))
		goto cleanup;
	old_duration = skel->bss->twq_end_ns - skel->bss->twq_start_ns;

	/* Limit cpu. */
	err = write_cgroup_file(TEST_CGROUP, "cpu.max", CPU_MAX_THROTTLED);
	if (!ASSERT_OK(err, "write cpu.max"))
		goto cleanup;
	err = write_cgroup_file(TEST_CGROUP, "cpu.uclamp.max", "20");
	if (!ASSERT_OK(err, "write cpu.uclamp.max"))
		goto cleanup;

	/* Test with cpu limit. */
	LIBBPF_OPTS_RESET(topts);
	if (!ASSERT_OK((bpf_prog_test_run_opts(prog_fd, &topts) ||
			topts.retval),
			"bpf_prog_test_run_opts with limit"))
		goto cleanup;
	for (waited_secs = 0; waited_secs < WAIT_TIMEOUT_SECS; waited_secs++) {
		if (skel->bss->twq_done)
			break;
		sleep(1);
	}
	if (!ASSERT_TRUE(skel->bss->twq_done, "twq_done with limit"))
		goto cleanup;
	new_duration = skel->bss->twq_end_ns - skel->bss->twq_start_ns;

	ASSERT_GT(new_duration, old_duration,
		"with cpu limit");

cleanup:
	if (skel) {
		thread_wq_cgroup__destroy(skel);
		/* Wait thread_wq kthread quit. */
		sleep(2);
	}
	if (cg_fd >= 0)
		close(cg_fd);
	cleanup_cgroup_environment();
}
