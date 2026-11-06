// SPDX-License-Identifier: GPL-2.0
/*
 * Drive the memcg_ops_protection sample: check that the kernel consults
 * low_request during reclaim, that the ctx describes the check faithfully,
 * and - the point of the test - that what the policy asks for is arbitrated
 * like a declared memory.low rather than granted outright.
 *
 * Layout, under the test workdir:
 *
 *   memcg_ops_prot                P   reclaim runs from P/memory.reclaim
 *   memcg_ops_prot/budget         M   memory.low is the budget C is capped to
 *   memcg_ops_prot/budget/victim  C   holds the memory, carries the ops
 *   memcg_ops_prot_ctl            -   where the test process normally sits
 *
 * The victim asks for its current usage (8M) on every pass.  The runner
 * varies M's memory.low - the budget the request is arbitrated against -
 * and reads the outcome back two ways: @threshold in the ctx of the next
 * pass carries the effective value the last pass computed, and C's
 * memory.events "low" counts the passes that skipped C as protected.
 *
 *   budget   request   elow(C)         C's memory.events low
 *   0        off       0               unchanged (nothing asked, nothing got)
 *   2M       on        2M, capped      unchanged (asked 8M, parent affords 2M)
 *   16M      on        usage, granted  increased (parent affords all of it)
 *
 * The middle row is the ceiling: the request can move protection around
 * inside the parent's budget but cannot lift the subtree above it.  Break
 * the cap in effective_protection() and that row turns red - elow(C)
 * becomes usage, reclaim skips C, and the event counter moves.
 *
 * The test process joins C itself and faults in 8M of anonymous memory.
 * Nothing is actually reclaimed - without swap there is nothing to take -
 * so each trigger walks the subtree repeatedly and returns EAGAIN, and
 * every walk consulted the hook and recomputed the effective value.  No
 * file is involved on purpose: a VM's working directory is often a shared
 * mount where temporary files are unsupported or unevictable.  On the way
 * out the process rejoins the ctl cgroup, so the framework's cleanup can
 * rmdir C, M and P.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <test_progs.h>
#include "cgroup_helpers.h"
#include "memcg_ops_protection.skel.h"

#define CTL_PATH	"/memcg_ops_prot_ctl"
#define PARENT_PATH	"/memcg_ops_prot"
#define BUDGET_PATH	PARENT_PATH "/budget"
#define VICTIM_PATH	BUDGET_PATH "/victim"

#define FILL_SZ		(8UL << 20)
#define RECLAIM_SZ	"1M"
/* Below FILL_SZ, so the request overclaims and the cap has to bite. */
#define BUDGET_CAPPED	(2UL << 20)
/* Above FILL_SZ, so the parent affords the request in full. */
#define BUDGET_GRANTED	(16UL << 20)

static int set_budget(unsigned long sz)
{
	char buf[32];

	snprintf(buf, sizeof(buf), "%lu", sz);
	return write_cgroup_file(BUDGET_PATH, "memory.low", buf);
}

/* .bss is frozen once the skeleton is loaded, so the phase switch that the
 * policy reads lives in a map rather than in a global.
 */
static int set_request(struct memcg_ops_protection *skel, int on)
{
	__u32 key = 0, val = !!on;

	return bpf_map_update_elem(bpf_map__fd(skel->maps.cfg), &key, &val, 0);
}

static long events_low(const char *path)
{
	char buf[512];
	char *p;

	if (read_cgroup_file(path, "memory.events", buf, sizeof(buf)))
		return -1;
	/* "low" is the first key in memory.events. */
	p = strstr(buf, "low ");
	if (!p)
		return -1;
	return strtol(p + 4, NULL, 10);
}

/* One triggered reclaim walk.  EAGAIN is as good a scan as success. */
static int trigger_reclaim(int pfd)
{
	ssize_t n;
	int rfd, err;

	rfd = openat(pfd, "memory.reclaim", O_RDWR);
	if (rfd < 0) {
		log_err("open memory.reclaim");
		return -1;
	}
	n = write(rfd, RECLAIM_SZ, sizeof(RECLAIM_SZ) - 1);
	err = n < 0 ? -errno : 0;
	close(rfd);
	if (err && err != -EAGAIN) {
		log_err("write memory.reclaim");
		return -1;
	}
	return 0;
}

void test_memcg_ops_protection(void)
{
	struct memcg_ops_protection *skel = NULL;
	struct bpf_link *ops_link = NULL;
	int ctlfd = -1, pfd = -1, bfd = -1, cfd = -1;
	__u64 seq_before, threshold, usage;
	long budget_pages, low_before, low_after;
	void *mem = MAP_FAILED;

	/* Sets the environment up and parks this process outside of P. */
	ctlfd = test__join_cgroup(CTL_PATH);
	if (!ASSERT_GE(ctlfd, 0, "join_cgroup"))
		return;

	pfd = create_and_get_cgroup(PARENT_PATH);
	if (!ASSERT_GE(pfd, 0, "create_parent"))
		goto done;

	bfd = create_and_get_cgroup(BUDGET_PATH);
	if (!ASSERT_GE(bfd, 0, "create_budget"))
		goto done;

	cfd = create_and_get_cgroup(VICTIM_PATH);
	if (!ASSERT_GE(cfd, 0, "create_victim"))
		goto done;

	/*
	 * The memory.* files of M and C need the memory controller in the
	 * subtree_control of P and of M.  A failure here is the usual "v1
	 * still owns memory", which is a skip rather than a fail.
	 */
	if (enable_controllers(PARENT_PATH, "memory") ||
	    enable_controllers(BUDGET_PATH, "memory")) {
		fprintf(stderr, "no memory controller under %s\n", PARENT_PATH);
		test__skip();
		goto done;
	}

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

	budget_pages = BUDGET_CAPPED / sysconf(_SC_PAGESIZE);

	/*
	 * Phase 0 - nothing declared, nothing requested.  The hook still
	 * runs: reclaim asks every cgroup it visits, protected or not.
	 */
	if (!ASSERT_OK(set_budget(0), "budget_zero"))
		goto done;
	if (!ASSERT_OK(set_request(skel, 0), "request_off"))
		goto done;
	seq_before = skel->bss->record_seq;
	low_before = events_low(VICTIM_PATH);
	if (!ASSERT_GE(low_before, 0, "events_phase0"))
		goto done;
	if (!ASSERT_OK(trigger_reclaim(pfd), "trigger_phase0"))
		goto done;

	if (!ASSERT_GT(skel->bss->record_seq, seq_before, "passes_phase0"))
		goto done;
	if (!ASSERT_EQ(skel->bss->saw_from_parent, 1, "target_phase0"))
		goto done;
	/* No claim anywhere below P, so C ends up with no protection. */
	if (!ASSERT_EQ(skel->bss->seen_threshold, 0ULL, "idle_threshold"))
		goto done;
	low_after = events_low(VICTIM_PATH);
	if (!ASSERT_EQ(low_after, low_before, "idle_events"))
		goto done;

	/*
	 * Phase 1 - the ceiling.  C asks for its full usage but M only
	 * affords BUDGET_CAPPED, so the arbitration has to cut the request
	 * down: elow(C) lands at the budget, below usage, and reclaim does
	 * not treat C as protected.
	 */
	if (!ASSERT_OK(set_budget(BUDGET_CAPPED), "budget_capped"))
		goto done;
	if (!ASSERT_OK(set_request(skel, 1), "request_on"))
		goto done;
	seq_before = skel->bss->record_seq;
	low_before = events_low(VICTIM_PATH);
	if (!ASSERT_GE(low_before, 0, "events_phase1"))
		goto done;
	if (!ASSERT_OK(trigger_reclaim(pfd), "trigger_phase1"))
		goto done;

	if (!ASSERT_GT(skel->bss->record_seq, seq_before, "passes_phase1"))
		goto done;
	threshold = skel->bss->seen_threshold;
	usage = skel->bss->seen_usage;
	if (!ASSERT_GT(usage, 0ULL, "capped_usage"))
		goto done;
	/*
	 * The request was honoured - it is what lifts elow off zero - and
	 * capped - it never exceeds what M affords.  Exact equality with
	 * the budget is the normal outcome; the cap is the invariant.
	 */
	if (!ASSERT_GT(threshold, 0ULL, "capped_threshold_nonzero"))
		goto done;
	if (!ASSERT_LE(threshold, (__u64)budget_pages, "capped_threshold"))
		goto done;
	if (!ASSERT_LT(threshold, usage, "capped_below_usage"))
		goto done;
	low_after = events_low(VICTIM_PATH);
	if (!ASSERT_EQ(low_after, low_before, "capped_events"))
		goto done;

	/*
	 * Phase 2 - the same request, but now M affords all of it: elow(C)
	 * reaches usage, reclaim skips C as protected, and the skip shows
	 * up in C's memory.events.  Together with phase 1 this pins the
	 * request to the arbitration: same ask, different budget,
	 * different outcome.
	 */
	if (!ASSERT_OK(set_budget(BUDGET_GRANTED), "budget_granted"))
		goto done;
	seq_before = skel->bss->record_seq;
	low_before = events_low(VICTIM_PATH);
	if (!ASSERT_GE(low_before, 0, "events_phase2"))
		goto done;
	if (!ASSERT_OK(trigger_reclaim(pfd), "trigger_phase2"))
		goto done;

	if (!ASSERT_GT(skel->bss->record_seq, seq_before, "passes_phase2"))
		goto done;
	threshold = skel->bss->seen_threshold;
	usage = skel->bss->seen_usage;
	/* The budget covers the ask, so the request is granted in full. */
	if (!ASSERT_EQ(threshold, usage, "granted_threshold"))
		goto done;
	if (!ASSERT_GT(usage, 0ULL, "granted_usage"))
		goto done;
	low_after = events_low(VICTIM_PATH);
	ASSERT_GT(low_after, low_before, "granted_events");

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
	if (bfd >= 0)
		close(bfd);
	if (pfd >= 0)
		close(pfd);
	if (ctlfd >= 0)
		close(ctlfd);
}
