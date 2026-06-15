// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026
 *
 * Test bpf_thread_wq with cgroup CPU throttling.
 *
 * Creates two cgroups:
 *   1. "thread_wq_test/fast" — no CPU limit (for bpf_wq baseline)
 *   2. "thread_wq_test/slow" — cpu.max = "1000 100000" (1% CPU)
 *
 * Runs the same burn_cpu() workload via bpf_wq (unthrottled system wq)
 * and bpf_thread_wq (worker kthread placed in the "slow" cgroup).
 *
 * Asserts that bpf_thread_wq takes significantly longer due to CPU limit.
 */
#include <test_progs.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "cgroup_helpers.h"
#include "thread_wq_cgroup.skel.h"

#define SLOW_CGROUP "thread_wq_test"
#define CPU_MAX_THROTTLED "1000 100000"  /* 1% of CPU bandwidth */
#define WAIT_TIMEOUT_MS 30000  /* 30s max wait — throttled work is slow */

void serial_test_thread_wq_cgroup(void)
{
	struct thread_wq_cgroup *skel = NULL;
	int err, prog_fd, cg_fd = -1;
	unsigned long long cg_id;
	__u64 wq_duration, twq_duration;
	int waited_ms;

	LIBBPF_OPTS(bpf_test_run_opts, topts);

	/* Setup cgroup environment (mounts cgroupfs if needed) */
	err = setup_cgroup_environment();
	if (!ASSERT_OK(err, "setup_cgroup_environment"))
		return;

	/* Create the throttled cgroup */
	cg_fd = create_and_get_cgroup(SLOW_CGROUP);
	if (!ASSERT_GE(cg_fd, 0, "create_and_get_cgroup"))
		goto cleanup;

	/* Apply CPU throttle: 1000us per 100000us period = 1% CPU */
	err = write_cgroup_file(SLOW_CGROUP, "cpu.max", CPU_MAX_THROTTLED);
	if (!ASSERT_OK(err, "write cpu.max"))
		goto cleanup;

	/* Get cgroup id for the BPF program */
	cg_id = get_cgroup_id(SLOW_CGROUP);
	if (!ASSERT_GT(cg_id, (unsigned long long)0, "get_cgroup_id"))
		goto cleanup;

	/* Load and prepare the BPF skeleton */
	skel = thread_wq_cgroup__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto cleanup;

	/* Set target cgroup for bpf_thread_wq */
	skel->bss->target_cgroup_id = cg_id;

	/* --- Run bpf_wq (unthrottled baseline) --- */
	prog_fd = bpf_program__fd(skel->progs.start_wq);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "run start_wq");
	ASSERT_EQ(topts.retval, 0, "start_wq retval");
	ASSERT_EQ(skel->bss->err_wq, 0, "err_wq");

	/* Wait for bpf_wq completion */
	for (waited_ms = 0; waited_ms < WAIT_TIMEOUT_MS; waited_ms += 10) {
		if (skel->bss->wq_done)
			break;
		usleep(10000);
	}
	if (!ASSERT_TRUE(skel->bss->wq_done, "wq_done"))
		goto cleanup;

	/* --- Run bpf_thread_wq (throttled) --- */
	LIBBPF_OPTS_RESET(topts);
	prog_fd = bpf_program__fd(skel->progs.start_thread_wq);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "run start_thread_wq");
	ASSERT_EQ(topts.retval, 0, "start_thread_wq retval");
	ASSERT_EQ(skel->bss->err_twq, 0, "err_twq");

	/* Wait for bpf_thread_wq completion (may take much longer) */
	for (waited_ms = 0; waited_ms < WAIT_TIMEOUT_MS; waited_ms += 10) {
		if (skel->bss->twq_done)
			break;
		usleep(10000);
	}
	if (!ASSERT_TRUE(skel->bss->twq_done, "twq_done"))
		goto cleanup;

	/* --- Compare execution times --- */
	wq_duration = skel->bss->wq_end_ns - skel->bss->wq_start_ns;
	twq_duration = skel->bss->twq_end_ns - skel->bss->twq_start_ns;

	printf("  bpf_wq duration:        %llu ns (%llu ms)\n",
	       wq_duration, wq_duration / 1000000);
	printf("  bpf_thread_wq duration: %llu ns (%llu ms)\n",
	       twq_duration, twq_duration / 1000000);
	printf("  slowdown ratio:         %.1fx\n",
	       (double)twq_duration / (double)wq_duration);

	/*
	 * With 1% CPU cap, the throttled worker should be at least 10x slower.
	 * Use a conservative 5x threshold to avoid flakiness on loaded machines.
	 */
	ASSERT_GT(twq_duration, wq_duration * 5,
		  "thread_wq should be significantly slower under CPU throttle");

cleanup:
	thread_wq_cgroup__destroy(skel);
	if (cg_fd >= 0)
		close(cg_fd);
	cleanup_cgroup_environment();
}
