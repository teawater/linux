// SPDX-License-Identifier: GPL-2.0
/*
 * Drive the memcg_ops_lockholder sample: put a cgroup over memory.high,
 * make the kernfs notify worker charge that cgroup while it holds the
 * cgroupfs locks, and check that the attached policy kept inline
 * enforcement away from it.
 *
 * The charge comes from fsnotify, which bills the delivery of an event to
 * the memcg of the group that asked for it.  So the watches have to be
 * created by a task inside the cgroup under test, and memory.events is the
 * file to watch: it is notified by the very reclaim that an over-high cgroup
 * runs.
 */

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <test_progs.h>
#include "cgroup_helpers.h"
#include "memcg_ops_lockholder.skel.h"

#define CGROUP_PATH	"/memcg_ops_lockholder"
#define MEM_HIGH	"1M"
#define OVERAGE_SZ	(8UL << 20)
#define RETOUCH_SZ	(2UL << 20)
#define NR_WATCHES	64
#define MIN_WATCHES	8
#define CHURN_ROUNDS	32
#define MAX_LINKS	32
#define POLL_US		1000
#define WAIT_LOOPS	(20 * 1000 * 1000 / POLL_US)

/*
 * One notification is worth one event per watch, and an event is a few dozen
 * bytes, which the per-cpu object stock of the cgroup swallows whole: it takes
 * a page worth of them before a charge reaches try_charge_memcg() again, and
 * the debt one charge adds is exactly the batch the inline enforcement needs
 * to be *more* than.  Watching the same files from many groups turns one
 * notification into a batch of charges and clears both hurdles at once.
 *
 * fs.inotify.max_user_instances caps how many groups there can be, and it is
 * per user rather than per test, so settle for whatever it allows.
 */
static int watch_memory_events(void)
{
	static const char * const files[] = {
		"memory.events", "memory.events.local",
	};
	int fd, i, j;

	for (i = 0; i < NR_WATCHES; i++) {
		fd = inotify_init1(IN_NONBLOCK);
		if (fd < 0)
			break;
		for (j = 0; j < ARRAY_SIZE(files); j++) {
			if (inotify_add_watch(fd, files[j], IN_MODIFY) >= 0)
				continue;
			fprintf(stderr, "child: watch %s: %s\n", files[j],
				strerror(errno));
			return -1;
		}
		/* Left open on purpose: the fds die with this task. */
	}

	if (i < MIN_WATCHES) {
		fprintf(stderr, "child: only %d inotify instances: %s\n", i,
			strerror(errno));
		return -1;
	}
	if (i < NR_WATCHES)
		fprintf(stderr, "child: %d of %d inotify instances\n", i,
			NR_WATCHES);

	return 0;
}

/*
 * The cgroup has nothing reclaimable, so a task in it that charges memory is
 * throttled for up to two seconds on every return to userspace.  Everything
 * this test checks lives in the skeleton rather than in that task, so the
 * parent does not wait for it: it polls for a deferral and kills it.
 */
static void breach_and_churn(int cgfd)
{
	char *mem;
	int i;

	if (fchdir(cgfd)) {
		fprintf(stderr, "child: fchdir: %s\n", strerror(errno));
		_exit(1);
	}

	/*
	 * Take the cgroupfs locks once, while nothing is over its limit.  The
	 * policy tracks holders in per-task storage, and a task whose storage
	 * could not be created looks exactly like one that holds nothing.
	 */
	mkdir("warmup", 0700);
	rmdir("warmup");

	/*
	 * The notify worker delivers with both kernfs locks held for read, and
	 * inotify_init1() records the memcg this task is in as the one that
	 * pays for the delivery.
	 */
	if (watch_memory_events())
		_exit(1);

	/*
	 * Touch the overage while memory.high is still "max", so that these
	 * charges build no debt and cannot be throttled.
	 */
	mem = mmap(NULL, OVERAGE_SZ, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mem == MAP_FAILED) {
		fprintf(stderr, "child: mmap: %s\n", strerror(errno));
		_exit(1);
	}
	memset(mem, 0xa5, OVERAGE_SZ);

	/*
	 * The helpers name the workdir after the pid of the test, so from a
	 * child it takes the _parent() variant to find the same one.
	 */
	if (write_cgroup_file_parent(CGROUP_PATH, "memory.high", MEM_HIGH)) {
		fprintf(stderr, "child: cannot set memory.high\n");
		_exit(1);
	}

	/*
	 * Charge again, now that the limit is in place.  Drop the pages first
	 * so that these faults are new charges rather than writes to memory
	 * the cgroup already owns: the reclaim they provoke is what notifies
	 * memory.events, and the slab the churn below allocates may well be
	 * served from the per-cpu stock without ever reaching the counter.
	 */
	if (madvise(mem, RETOUCH_SZ, MADV_DONTNEED)) {
		fprintf(stderr, "child: madvise: %s\n", strerror(errno));
		_exit(1);
	}
	memset(mem, 0xa5, RETOUCH_SZ);

	/*
	 * Every charge from here on is over memory.high, and the reclaim a
	 * task runs to pay its debt notifies memory.events, which sends the
	 * worker back into this cgroup with the locks held.  The churn adds
	 * charges and notifications of its own.
	 */
	for (i = 0; i < CHURN_ROUNDS; i++) {
		mkdir("kid", 0700);
		rmdir("kid");
	}

	/* Let the parent kill this task rather than serve the throttle. */
	pause();
	_exit(0);
}

/*
 * Say what the cgroup looked like, so that a run with no deferral can be told
 * apart from one where the pressure was never there.
 */
static void report_cgroup(int status, bool exited)
{
	char events[512] = "", high[64] = "";

	read_cgroup_file(CGROUP_PATH, "memory.high", high, sizeof(high) - 1);
	read_cgroup_file(CGROUP_PATH, "memory.events", events,
			 sizeof(events) - 1);
	high[strcspn(high, "\n")] = '\0';

	if (exited)
		fprintf(stderr, "child exited with %d, ", WEXITSTATUS(status));
	fprintf(stderr, "memory.high=%s, memory.events:\n%s", high, events);
}

void test_memcg_ops_lockholder(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct memcg_ops_lockholder *skel = NULL;
	struct bpf_link *links[MAX_LINKS] = {};
	struct bpf_link *ops_link = NULL;
	struct bpf_program *prog;
	bool exited = false;
	int cgfd, nr_links = 0, status = 0, i;
	pid_t pid;

	cgfd = test__join_cgroup(CGROUP_PATH);
	if (!ASSERT_GE(cgfd, 0, "join_cgroup"))
		return;

	/*
	 * All the pressure below goes through memory.high, so the memory
	 * controller has to be available in this hierarchy.  It is not, for
	 * example, when it is still claimed by cgroup v1.
	 */
	if (write_cgroup_file(CGROUP_PATH, "memory.high", "max")) {
		char controllers[256] = "";

		read_cgroup_file("", "cgroup.controllers", controllers,
				 sizeof(controllers) - 1);
		controllers[strcspn(controllers, "\n")] = '\0';
		fprintf(stderr, "no memory controller, cgroup.controllers: %s\n",
			controllers);
		test__skip();
		goto done;
	}

	skel = memcg_ops_lockholder__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		goto done;

	if (!ASSERT_OK(memcg_ops_lockholder__load(skel), "load"))
		goto done;

	/*
	 * resolve_locks() fills in the two addresses every hook filters on,
	 * so it has to run before any of them is attached.
	 */
	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.resolve_locks),
					      &topts), "run_resolve_locks"))
		goto done;
	if (!ASSERT_EQ(topts.retval, 0, "resolve_locks"))
		goto done;
	if (!ASSERT_NEQ(skel->bss->kernfs_rwsem_addr, 0ULL, "kernfs_rwsem_addr"))
		goto done;
	if (!ASSERT_NEQ(skel->bss->kernfs_supers_rwsem_addr, 0ULL,
			"kernfs_supers_rwsem_addr"))
		goto done;

	/* The hooks and the syscall program: only the hooks get attached. */
	bpf_object__for_each_program(prog, skel->obj) {
		if (bpf_program__type(prog) != BPF_PROG_TYPE_TRACING)
			continue;

		if (!ASSERT_LT(nr_links, MAX_LINKS, "nr_links"))
			goto done;

		links[nr_links] = bpf_program__attach(prog);
		if (!ASSERT_OK_PTR(links[nr_links], bpf_program__name(prog)))
			goto done;
		nr_links++;
	}

	ops_link = bpf_map__attach_cgroup_opts(skel->maps.kernfs_lockholder,
					       cgfd, NULL);
	if (!ASSERT_OK_PTR(ops_link, "attach_ops"))
		goto done;

	pid = fork();
	if (pid == 0) {
		breach_and_churn(cgfd);
		_exit(1);
	}
	if (!ASSERT_GE(pid, 0, "fork"))
		goto done;

	/*
	 * Poll for the first deferral.  A child that is already gone cannot
	 * produce one, so there is nothing left to wait for either.
	 */
	for (i = 0; i < WAIT_LOOPS; i++) {
		if (skel->bss->deferrals)
			break;
		if (waitpid(pid, &status, WNOHANG) == pid) {
			exited = true;
			break;
		}
		usleep(POLL_US);
	}

	if (!exited) {
		kill(pid, SIGKILL);
		while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
			;
	}

	write_cgroup_file(CGROUP_PATH, "memory.high", "max");

	if (!ASSERT_GT(skel->bss->deferrals, 0ULL, "deferrals")) {
		report_cgroup(status, exited && WIFEXITED(status));
		fprintf(stderr,
			"passthroughs %llu violations %llu mark_failures %llu\n",
			(unsigned long long)skel->bss->passthroughs,
			(unsigned long long)skel->bss->violations,
			(unsigned long long)skel->bss->mark_failures);
	}

	/* A holder that reached inline enforcement means the policy failed. */
	ASSERT_EQ(skel->bss->violations, 0ULL, "violations");
	/* An untracked holder would have passed for the wrong reason. */
	ASSERT_EQ(skel->bss->mark_failures, 0ULL, "mark_failures");

done:
	bpf_link__destroy(ops_link);
	for (i = 0; i < nr_links; i++)
		bpf_link__destroy(links[i]);
	memcg_ops_lockholder__destroy(skel);
	close(cgfd);
}
