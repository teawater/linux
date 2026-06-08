// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 */
#include <test_progs.h>
#include "thread_wq.skel.h"

void serial_test_thread_wq(void)
{
	struct thread_wq *skel = NULL;
	int err, prog_fd;

	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = thread_wq__open_and_load();
	if (!ASSERT_OK_PTR(skel, "thread_wq__open_and_load"))
		return;

	/* Test array map */
	prog_fd = bpf_program__fd(skel->progs.test_thread_wq_array);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_thread_wq_array");
	ASSERT_EQ(topts.retval, 0, "test_thread_wq_array retval");

	usleep(50000); /* wait for the callback to execute */
	ASSERT_EQ(skel->bss->ok & (1 << 0), (1 << 0), "array callback executed");

	/* Test hash map */
	prog_fd = bpf_program__fd(skel->progs.test_thread_wq_hash);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_thread_wq_hash");
	ASSERT_EQ(topts.retval, 0, "test_thread_wq_hash retval");

	usleep(50000);
	ASSERT_EQ(skel->bss->ok & (1 << 1), (1 << 1), "hash callback executed");

	/* Test LRU map */
	prog_fd = bpf_program__fd(skel->progs.test_thread_wq_lru);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_thread_wq_lru");
	ASSERT_EQ(topts.retval, 0, "test_thread_wq_lru retval");

	usleep(50000);
	ASSERT_EQ(skel->bss->ok & (1 << 2), (1 << 2), "lru callback executed");

	thread_wq__destroy(skel);
}
