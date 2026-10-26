// SPDX-License-Identifier: GPL-2.0
/*
 * Drive the memcg_ops_protection sample: check that the kernel consults
 * min_policy and low_policy during reclaim, and that the ctx they receive
 * describes the check faithfully.  The policies themselves always say
 * NO_OPINION, so nothing about reclaim's outcome changes.
 *
 * Layout, under the test workdir:
 *
 *   memcg_ops_prot           P   reclaim runs from P/memory.reclaim
 *   memcg_ops_prot/victim    C   holds the memory, carries the ops
 *   memcg_ops_prot_ctl       -   where the test process normally sits
 *
 * The test process joins C itself and faults in 8M of anonymous memory:
 * C's usage above its zero emin/elow is exactly what makes the kernel ask
 * the hooks.  Nothing is actually reclaimed -- without swap there is
 * nothing to take -- so the write returns EAGAIN after seventeen full
 * scans, and every one of them consulted the hooks.  No file is involved
 * on purpose: a VM's working directory is often a shared mount where
 * temporary files are unsupported or unevictable.  On the way out the
 * process rejoins the ctl cgroup, so the framework's cleanup can rmdir
 * C and P.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include <test_progs.h>
#include "cgroup_helpers.h"
#include "memcg_ops_protection.skel.h"

#define CTL_PATH	"/memcg_ops_prot_ctl"
#define PARENT_PATH	"/memcg_ops_prot"
#define VICTIM_PATH	PARENT_PATH "/victim"

#define FILL_SZ		(8UL << 20)
#define RECLAIM_SZ	"1M"

void test_memcg_ops_protection(void)
{
	struct memcg_ops_protection *skel = NULL;
	struct bpf_link *ops_link = NULL;
	int ctlfd = -1, pfd = -1, cfd = -1, rfd;
	void *mem = MAP_FAILED;
	ssize_t n;
	int err;

	/* Sets the environment up and parks this process outside of P. */
	ctlfd = test__join_cgroup(CTL_PATH);
	if (!ASSERT_GE(ctlfd, 0, "join_cgroup"))
		return;

	pfd = create_and_get_cgroup(PARENT_PATH);
	if (!ASSERT_GE(pfd, 0, "create_parent"))
		goto done;

	/*
	 * The victim's memory.* files need the memory controller in P's
	 * subtree_control.  A failure here is the usual "v1 still owns
	 * memory", which is a skip rather than a fail.
	 */
	if (enable_controllers(PARENT_PATH, "memory")) {
		fprintf(stderr, "no memory controller under %s\n", PARENT_PATH);
		test__skip();
		goto done;
	}

	cfd = create_and_get_cgroup(VICTIM_PATH);
	if (!ASSERT_GE(cfd, 0, "create_victim"))
		goto done;

	skel = memcg_ops_protection__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		goto done;

	skel->bss->target_cgroup_id = get_cgroup_id(VICTIM_PATH);
	skel->bss->parent_cgroup_id = get_cgroup_id(PARENT_PATH);
	if (!ASSERT_NEQ(skel->bss->target_cgroup_id, 0ULL, "victim_id"))
		goto done;
	if (!ASSERT_NEQ(skel->bss->parent_cgroup_id, 0ULL, "parent_id"))
		goto done;

	if (!ASSERT_OK(memcg_ops_protection__load(skel), "load"))
		goto done;

	ops_link = bpf_map__attach_cgroup_opts(skel->maps.prot_ops, cfd, NULL);
	if (!ASSERT_OK_PTR(ops_link, "attach_ops"))
		goto done;

	/* From here on the test process lives in C; leave via done. */
	if (!ASSERT_OK(join_cgroup(VICTIM_PATH), "join_victim"))
		goto done;

	mem = mmap(NULL, FILL_SZ, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (!ASSERT_TRUE(mem != MAP_FAILED, "mmap"))
		goto done;
	memset(mem, 0xa5, FILL_SZ);

	/* The trigger.  EAGAIN is as good a scan as success. */
	rfd = openat(pfd, "memory.reclaim", O_RDWR);
	if (!ASSERT_GE(rfd, 0, "open_reclaim"))
		goto done;
	n = write(rfd, RECLAIM_SZ, sizeof(RECLAIM_SZ) - 1);
	err = n < 0 ? -errno : 0;
	close(rfd);
	if (!ASSERT_TRUE(err == 0 || err == -EAGAIN, "reclaim_trigger"))
		goto done;

	/* Both hooks run for one unprotected cgroup in one scan. */
	if (!ASSERT_GT(skel->bss->min_calls, 0ULL, "min_calls"))
		goto done;
	if (!ASSERT_GT(skel->bss->low_calls, 0ULL, "low_calls"))
		goto done;

	/* The victim has no memory.min/low, and it is not empty. */
	if (!ASSERT_EQ(skel->bss->seen_min_threshold, 0ULL, "emin"))
		goto done;
	if (!ASSERT_GT(skel->bss->seen_min_usage, 0ULL, "min_usage"))
		goto done;
	if (!ASSERT_EQ(skel->bss->seen_low_threshold, 0ULL, "elow"))
		goto done;
	if (!ASSERT_GT(skel->bss->seen_low_usage, 0ULL, "low_usage"))
		goto done;

	/* The reclaim came from P, and the ctx said so. */
	if (!ASSERT_EQ(skel->bss->saw_min_from_parent, 1, "min_target"))
		goto done;
	ASSERT_EQ(skel->bss->saw_low_from_parent, 1, "low_target");

done:
	/* Detach before anything else: no policy may run during teardown. */
	bpf_link__destroy(ops_link);
	memcg_ops_protection__destroy(skel);
	if (mem != MAP_FAILED)
		munmap(mem, FILL_SZ);
	/* A no-op when the process never made it into the victim. */
	join_cgroup(CTL_PATH);
	if (cfd >= 0)
		close(cfd);
	if (pfd >= 0)
		close(pfd);
	if (ctlfd >= 0)
		close(ctlfd);
}
