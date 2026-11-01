// probe.c: runs inside the guest and tries every wall the lean kernel claims to have.
// Each check runs as root first (cut code must be absent even for root), then as an
// unprivileged user (uid 65534) for the checks that depend on privilege. With --jailed it runs
// a third set under guest/jail-exec to prove the seccomp filter blocks what the kernel can't cut.
// Positive controls make sure a broken guest can't pass by failing everything.
// Prints PASS/FAIL/INFO/SURFACE lines and "PROBE: ... N passed, M failed"; exits 1 on any FAIL.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>

#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif
#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif
#define NETLINK_XFRM 6
#define NETLINK_NETFILTER 12

static int passed, failed;
static const char *who = "root";

static void result(int ok, const char *name, const char *detail)
{
	printf("%s [%s] %s: %s\n", ok ? "PASS" : "FAIL", who, name, detail);
	ok ? passed++ : failed++;
}

static void info(const char *name, const char *detail)
{
	printf("INFO [%s] %s: %s\n", who, name, detail);
}

// rc < 0 with errno == want is a pass; anything else (including success) is a fail.
static void expect_errno(const char *name, long rc, int want)
{
	char d[96];
	int e = errno;
	if (rc >= 0)
		snprintf(d, sizeof d, "succeeded (rc=%ld), wanted %s", rc, strerror(want));
	else
		snprintf(d, sizeof d, "%s", strerror(e));
	result(rc < 0 && e == want, name, d);
}

static void expect_absent(const char *path)
{
	char name[96];
	snprintf(name, sizeof name, "absent %s", path);
	errno = 0;
	expect_errno(name, access(path, F_OK), ENOENT);
}

static void expect_no_socket(const char *name, int domain, int type, int proto, int want)
{
	long fd = socket(domain, type, proto);
	int e = errno;
	if (fd >= 0)
		close(fd);
	errno = e;
	expect_errno(name, fd, want);
}

// Run fn in a child; pass if the child dies from sig.
static void expect_signal(const char *name, void (*fn)(void), int sig)
{
	char d[64];
	int st;
	pid_t p = fork();
	if (p == 0) {
		fn();
		_exit(0);
	}
	waitpid(p, &st, 0);
	if (WIFSIGNALED(st))
		snprintf(d, sizeof d, "killed by signal %d", WTERMSIG(st));
	else
		snprintf(d, sizeof d, "exited %d, wanted signal %d", WEXITSTATUS(st), sig);
	result(WIFSIGNALED(st) && WTERMSIG(st) == sig, name, d);
}

static void do_int80(void) { __asm__ volatile("int $0x80" : : "a"(20) : "memory"); }
static void do_vsyscall(void) { (void)*(volatile long *)0xffffffffff600000UL; }
// Strict mode allows only read/write/exit/sigreturn, so getpid must kill the process.
static void do_seccomp_strict(void)
{
	if (prctl(PR_SET_SECCOMP, 1 /* SECCOMP_MODE_STRICT */, 0, 0, 0) == 0)
		syscall(SYS_getpid);
	syscall(SYS_exit, 0);
}

static void cut_syscalls(void)
{
	char buf[256] = {0};
	unsigned long ctx = 0;

	expect_errno("io_uring_setup", syscall(SYS_io_uring_setup, 1, buf), ENOSYS);
	expect_errno("bpf", syscall(SYS_bpf, 0, buf, 64), ENOSYS);
	expect_errno("userfaultfd", syscall(SYS_userfaultfd, 0), ENOSYS);
	expect_errno("kcmp", syscall(SYS_kcmp, getpid(), getpid(), 0, 0, 0), ENOSYS);
	expect_errno("io_setup (AIO)", syscall(SYS_io_setup, 1, &ctx), ENOSYS);
	expect_errno("rseq", syscall(SYS_rseq, NULL, 0, 0, 0), ENOSYS);
	expect_errno("kexec_load", syscall(SYS_kexec_load, 0, 0, NULL, 0), ENOSYS);
	expect_errno("kexec_file_load", syscall(SYS_kexec_file_load, -1, -1, 0, "", 0), ENOSYS);
	expect_errno("init_module", syscall(SYS_init_module, buf, 0, ""), ENOSYS);
	expect_errno("finit_module", syscall(SYS_finit_module, -1, "", 0), ENOSYS);
	expect_errno("modify_ldt", syscall(SYS_modify_ldt, 0, buf, sizeof buf), ENOSYS);
	expect_errno("iopl", syscall(SYS_iopl, 3), ENOSYS);
	expect_errno("ioperm", syscall(SYS_ioperm, 0x80, 1, 1), ENOSYS);
	expect_errno("uselib", syscall(SYS_uselib, "/nonexistent"), ENOSYS);
	expect_errno("sysfs syscall", syscall(SYS_sysfs, 3), ENOSYS);
	expect_errno("unshare(CLONE_NEWUSER)", unshare(CLONE_NEWUSER), EINVAL);
	expect_errno("msgget (SYSVIPC)", syscall(SYS_msgget, 0, 01000 | 0600), ENOSYS);
	expect_errno("semget (SYSVIPC)", syscall(SYS_semget, 0, 1, 01000 | 0600), ENOSYS);
	expect_errno("shmget (SYSVIPC)", syscall(SYS_shmget, 0, 4096, 01000 | 0600), ENOSYS);
	expect_errno("mq_open (POSIX_MQUEUE)", syscall(SYS_mq_open, "probe", 0100 | 02, 0600, NULL), ENOSYS);
	expect_errno("add_key (KEYS)", syscall(SYS_add_key, "user", "probe", "x", 1, -3), ENOSYS);
	expect_errno("keyctl (KEYS)", syscall(SYS_keyctl, 0, -3, 0, 0, 0), ENOSYS);
	expect_errno("request_key (KEYS)", syscall(SYS_request_key, "user", "probe", NULL, 0), ENOSYS);
	expect_errno("set_mempolicy (NUMA)", syscall(SYS_set_mempolicy, 0, NULL, 0), ENOSYS);
	expect_errno("mbind (NUMA)", syscall(SYS_mbind, 0, 0, 0, NULL, 0, 0), ENOSYS);
	expect_errno("migrate_pages (NUMA)", syscall(SYS_migrate_pages, 0, 0, NULL, NULL), ENOSYS);
	expect_errno("move_pages (NUMA)", syscall(SYS_move_pages, 0, 0, NULL, NULL, NULL, 0), ENOSYS);
	expect_errno("quotactl (QUOTA)", syscall(SYS_quotactl, 0, NULL, 0, NULL), ENOSYS);
	expect_errno("quotactl_fd (QUOTA)", syscall(SYS_quotactl_fd, -1, 0, 0, NULL), ENOSYS);
	expect_errno("swapon (SWAP)", syscall(SYS_swapon, "/nonexistent", 0), ENOSYS);
	expect_errno("swapoff (SWAP)", syscall(SYS_swapoff, "/nonexistent"), ENOSYS);
	expect_errno("acct (BSD_PROCESS_ACCT)", syscall(SYS_acct, NULL), ENOSYS);
}

static void cut_sockets(void)
{
	expect_no_socket("AF_PACKET", AF_PACKET, SOCK_RAW, 0, EAFNOSUPPORT);
	expect_no_socket("AF_INET6", AF_INET6, SOCK_STREAM, 0, EAFNOSUPPORT);
	expect_no_socket("netlink XFRM", AF_NETLINK, SOCK_RAW, NETLINK_XFRM, EPROTONOSUPPORT);
	expect_no_socket("netlink NETFILTER", AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER, EPROTONOSUPPORT);
	expect_no_socket("IPPROTO_MPTCP", AF_INET, SOCK_STREAM, IPPROTO_MPTCP, EPROTONOSUPPORT);
}

static void cut_files(void)
{
	static const char *paths[] = {
		"/dev/mem", "/dev/kmem", "/dev/port", "/dev/fuse", "/dev/net/tun",
		"/dev/loop-control", "/dev/cpu/0/msr", "/dev/cpu/0/cpuid",
		"/proc/kcore", "/proc/kallsyms", "/proc/sysrq-trigger", "/proc/self/pagemap",
		"/proc/sys/kernel/core_pattern", "/proc/sys/kernel/io_uring_disabled",
		"/sys/kernel/debug", "/sys/kernel/tracing", "/sys/kernel/kexec_loaded",
	};
	for (size_t i = 0; i < sizeof paths / sizeof *paths; i++)
		expect_absent(paths[i]);
}

static void legacy_entry(void)
{
	expect_signal("32-bit int 0x80", do_int80, SIGSEGV);
	expect_signal("vsyscall page read", do_vsyscall, SIGSEGV);
}

// PROC_MEM_NO_FORCE: /proc/self/mem must not write through page protections.
static void proc_mem_no_force(void)
{
	char c = (char)0xcc;
	int fd = open("/proc/self/mem", O_RDWR);
	if (fd < 0) {
		result(1, "/proc/self/mem write to text", "cannot open (stricter than needed)");
		return;
	}
	errno = 0;
	long rc = pwrite(fd, &c, 1, (off_t)(uintptr_t)&do_int80);
	int e = errno;
	close(fd);
	char d[64];
	snprintf(d, sizeof d, "%s", rc == 1 ? "wrote read-only text" : strerror(e));
	result(rc != 1, "/proc/self/mem write to text", d);
}

static void positive_controls(void)
{
	char d[96];
	long fd;

	fd = socket(AF_VSOCK, SOCK_STREAM, 0);
	snprintf(d, sizeof d, "%s", fd >= 0 ? "ok" : strerror(errno));
	result(fd >= 0, "control: AF_VSOCK socket", d);
	if (fd >= 0)
		close(fd);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	snprintf(d, sizeof d, "%s", fd >= 0 ? "ok" : strerror(errno));
	result(fd >= 0, "control: AF_UNIX socket", d);
	if (fd >= 0)
		close(fd);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	info("AF_INET socket", fd >= 0 ? "available (tap profile)" : "unavailable (vsock-only profile)");
	if (fd >= 0)
		close(fd);

	long abi = syscall(SYS_landlock_create_ruleset, NULL, 0, 1 /* LANDLOCK_CREATE_RULESET_VERSION */);
	if (abi > 0)
		snprintf(d, sizeof d, "ABI %ld", abi);
	else
		snprintf(d, sizeof d, "%s", strerror(errno));
	result(abi > 0, "control: landlock", d);

	expect_signal("control: seccomp strict kills getpid", do_seccomp_strict, SIGKILL);
}

// Lockdown must be in confidentiality mode (root: mounts securityfs to read it).
static void lockdown_mode(void)
{
	char buf[128] = {0};
	mkdir("/tmp/sec", 0700);
	mount("none", "/tmp/sec", "securityfs", 0, NULL);
	int fd = open("/tmp/sec/lockdown", O_RDONLY);
	if (fd >= 0) {
		read(fd, buf, sizeof buf - 1);
		close(fd);
	}
	buf[strcspn(buf, "\n")] = 0;
	result(strstr(buf, "[confidentiality]") != NULL, "control: lockdown=confidentiality",
	       buf[0] ? buf : "lockdown file unreadable");
	umount("/tmp/sec");
}

// Unprivileged-only checks.
static void unpriv_checks(void)
{
	char d[96], buf[64];
	errno = 0;
	void *m = mmap((void *)0x1000, 4096, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	expect_errno("mmap below mmap_min_addr", m == MAP_FAILED ? -1 : 0, EPERM);
	if (m != MAP_FAILED)
		munmap(m, 4096);

	errno = 0;
	expect_errno("dmesg read (dmesg_restrict)", klogctl(3, buf, sizeof buf), EPERM);

	// Yama ptrace_scope=1: a same-uid sibling (not a descendant) can't be attached.
	pid_t target = fork();
	if (target == 0) {
		pause();
		_exit(0);
	}
	pid_t tracer = fork();
	if (tracer == 0)
		_exit(ptrace(PTRACE_ATTACH, target, 0, 0) == 0 ? 0 : errno);
	int st;
	waitpid(tracer, &st, 0);
	kill(target, SIGKILL);
	waitpid(target, NULL, 0);
	int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
	snprintf(d, sizeof d, "%s", code == 0 ? "attached to sibling" : strerror(code));
	result(code == EPERM, "ptrace sibling (yama)", d);

	// Root-only syscalls that are still compiled in: capability checks are what stop the agent.
	struct { unsigned int bytes; int type; unsigned char h[128]; } fh = { 128, 0, {0} };
	int mnt;
	syscall(SYS_name_to_handle_at, AT_FDCWD, "/", &fh, &mnt, 0);
	errno = 0; expect_errno("unshare(CLONE_NEWNS)", unshare(CLONE_NEWNS), EPERM);
	errno = 0; expect_errno("mount tmpfs", mount("none", "/tmp", "tmpfs", 0, NULL), EPERM);
	errno = 0; expect_errno("fsopen", syscall(SYS_fsopen, "tmpfs", 0), EPERM);
	errno = 0; expect_errno("chroot", chroot("/tmp"), EPERM);
	errno = 0; expect_errno("open_by_handle_at", syscall(SYS_open_by_handle_at, AT_FDCWD, &fh, 0), EPERM);
	errno = 0; expect_errno("settimeofday", syscall(SYS_settimeofday, NULL, NULL), EPERM);
	errno = 0; expect_errno("reboot", syscall(SYS_reboot, 0xfee1dead, 672274793, 0x4321fedc, NULL), EPERM);
	errno = 0; expect_errno("init pid ptrace", ptrace(PTRACE_ATTACH, 1, 0, 0), EPERM);

	struct perf_event_attr pa;
	memset(&pa, 0, sizeof pa);
	pa.size = sizeof pa;
	pa.type = PERF_TYPE_SOFTWARE;
	pa.config = PERF_COUNT_SW_CPU_CLOCK;
	pa.exclude_kernel = 1;
	long pfd = syscall(SYS_perf_event_open, &pa, 0, -1, -1, 0);
	if (pfd >= 0)
		snprintf(d, sizeof d, "open: unprivileged self-profiling allowed");
	else
		snprintf(d, sizeof d, "blocked: %s", strerror(errno));
	info("perf_event_open", d);
	if (pfd >= 0)
		close(pfd);
}

// Surface report (user only): syscalls still compiled in that show up in public exploits as
// heap-spray or race primitives. Reported, not failed: each needs a decision (cut the CONFIG or
// block it in the in-guest seccomp profile). "reachable" means the call worked unprivileged.
static void reach(const char *name, long rc)
{
	char d[96];
	if (rc >= 0)
		snprintf(d, sizeof d, "reachable");
	else
		snprintf(d, sizeof d, "refused: %s", strerror(errno));
	printf("SURFACE [user] %s: %s\n", name, d);
}

static void surface_report(void)
{
	char buf[64] = "x";
	long fd;

	errno = 0; reach("setxattr user.* on tmpfs", (fd = open("/tmp/probe-x", O_CREAT | O_WRONLY, 0600)) < 0 ? -1 :
		syscall(SYS_fsetxattr, fd, "user.probe", buf, 1, 0));
	if (fd >= 0) { close(fd); unlink("/tmp/probe-x"); }
	errno = 0; fd = syscall(SYS_memfd_create, "probe", 0);
	reach("memfd_create (fileless exec)", fd);
	if (fd >= 0) close(fd);
	int p[2];
	if (pipe(p) == 0) {
		struct iovec iov = { buf, 1 };
		errno = 0; reach("vmsplice", syscall(SYS_vmsplice, p[1], &iov, 1, 0));
		close(p[0]); close(p[1]);
	}
	errno = 0; fd = syscall(SYS_fanotify_init, 0, 0);
	reach("fanotify_init", fd);
	if (fd >= 0) close(fd);
	struct { unsigned int bytes; int type; unsigned char h[128]; } fh = { 128, 0, {0} };
	int mnt;
	errno = 0; reach("name_to_handle_at", syscall(SYS_name_to_handle_at, AT_FDCWD, "/", &fh, &mnt, 0));
	struct iovec l = { buf, 1 }, r = { buf + 1, 1 };
	errno = 0; reach("process_vm_readv (self)", syscall(SYS_process_vm_readv, getpid(), &l, 1, &r, 1, 0));
	errno = 0; fd = syscall(SYS_memfd_secret, 0);
	reach("memfd_secret", fd);
	if (fd >= 0) close(fd);

}

// The root image must be root-owned and not group/world-writable, or the agent's uid could
// rewrite what root runs at the next boot (mkfs.ext4 -d copies the build user's ownership).
static void rootfs_ownership(void)
{
	static const char *const paths[] = { "/", "/init", "/bin", "/bin/busybox", "/bin/probe",
					     "/bin/jail-exec", "/etc" };
	for (size_t i = 0; i < sizeof paths / sizeof paths[0]; i++) {
		char name[96], d[96];
		struct stat st;
		snprintf(name, sizeof name, "root-owned %s", paths[i]);
		if (lstat(paths[i], &st)) {
			result(0, name, strerror(errno));
			continue;
		}
		snprintf(d, sizeof d, "uid %u gid %u mode %04o", st.st_uid, st.st_gid, st.st_mode & 07777);
		result(st.st_uid == 0 && st.st_gid == 0 && !(st.st_mode & 0022), name, d);
	}
}

// jail-exec must refuse any UID that isn't 1..65534 before running anything. 4294967296 used to
// wrap to uid 0 and 4294967295 to (uid_t)-1 ("leave unchanged"): both kept root.
static void jail_exec_rejects(void)
{
	static const char *const bad[] = { "0", "-1", "65535", "4294967295", "4294967296",
					   "99999999999999999999", "+1", " 1", "01", "1x", "" };
	for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
		char name[96], d[96];
		snprintf(name, sizeof name, "jail-exec refuses uid \"%s\"", bad[i]);
		pid_t p = fork();
		if (p == 0) {
			int fd = open("/dev/null", O_WRONLY);
			if (fd >= 0)
				dup2(fd, 2);
			execl("/bin/jail-exec", "jail-exec", bad[i], "/bin/true", (char *)NULL);
			_exit(126);
		}
		int st = 0;
		waitpid(p, &st, 0);
		int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
		snprintf(d, sizeof d, code == 127 ? "refused" : "exit %d (127 = refused)", code);
		result(code == 127, name, d);
	}
}

static void expect_sysctl(const char *path, const char *want)
{
	char name[96], buf[32] = "";
	snprintf(name, sizeof name, "%s = %s", path + strlen("/proc/sys/"), want);
	FILE *f = fopen(path, "r");
	if (!f) {
		result(0, name, strerror(errno));
		return;
	}
	if (!fgets(buf, sizeof buf, f))
		buf[0] = 0;
	fclose(f);
	buf[strcspn(buf, "\n")] = 0;
	result(strcmp(buf, want) == 0, name, buf);
}

// Boot-time sysctls from vm/vm.json.in. kptr_restrict=2: %pK prints zeros, not hashes.
// memfd_noexec=2: no executable memfd, which closes memfd_create + execveat (fileless exec)
// on top of noexec writable mounts in the agent image.
static void boot_sysctls(void)
{
	expect_sysctl("/proc/sys/kernel/kptr_restrict", "2");
	expect_sysctl("/proc/sys/vm/memfd_noexec", "2");
	errno = 0;
	long fd = syscall(SYS_memfd_create, "probe-exec", 0x0010u /* MFD_EXEC */);
	expect_errno("memfd_create(MFD_EXEC)", fd, EACCES);
	if (fd >= 0)
		close((int)fd);
	// Without flags the kernel must hand out a non-executable, sealed memfd.
	errno = 0;
	fd = syscall(SYS_memfd_create, "probe-plain", 0);
	if (fd < 0) {
		result(0, "plain memfd is noexec", strerror(errno));
	} else {
		struct stat st;
		int ok = fstat((int)fd, &st) == 0 && !(st.st_mode & 0111);
		char d[64];
		snprintf(d, sizeof d, "mode %04o", ok ? st.st_mode & 07777 : 0);
		result(ok, "plain memfd is noexec", d);
		close((int)fd);
	}
}

static void run_all(void)
{
	cut_syscalls();
	cut_sockets();
	cut_files();
	legacy_entry();
	proc_mem_no_force();
	positive_controls();
}

static void do_x32_getpid(void) { syscall(SYS_getpid | 0x40000000); }
static void do_traceme(void) { _exit(ptrace(PTRACE_TRACEME, 0, 0, 0) == 0 ? 0 : errno); }

// Third pass, run under guest/jail-exec. Only calls an unprivileged process could otherwise make
// prove the filter works; root-only calls (mount, ...) fail with EPERM either way.
static int jailed_checks(void)
{
	char d[96], buf[8] = "x";
	who = "jailed";

	snprintf(d, sizeof d, "uid %d", (int)getuid());
	result(getuid() == 65534, "control: running as uid 65534", d);
	result(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1, "control: no_new_privs", "set");
	result(prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == 2, "control: seccomp filter mode", "mode 2");
	pid_t c = fork();
	if (c == 0)
		_exit(0);
	int st = -1;
	if (c > 0)
		waitpid(c, &st, 0);
	result(c > 0 && WIFEXITED(st) && WEXITSTATUS(st) == 0, "control: fork still works", c > 0 ? "ok" : strerror(errno));
	long fd = socket(AF_VSOCK, SOCK_STREAM, 0);
	result(fd >= 0, "control: AF_VSOCK socket", fd >= 0 ? "ok" : strerror(errno));
	if (fd >= 0)
		close(fd);

	struct perf_event_attr pa;
	memset(&pa, 0, sizeof pa);
	pa.size = sizeof pa;
	pa.type = PERF_TYPE_SOFTWARE;
	pa.config = PERF_COUNT_SW_CPU_CLOCK;
	pa.exclude_kernel = 1;
	errno = 0; expect_errno("perf_event_open", syscall(SYS_perf_event_open, &pa, 0, -1, -1, 0), EPERM);
	int p[2];
	if (pipe(p) == 0) {
		struct iovec iov = { buf, 1 };
		errno = 0; expect_errno("vmsplice", syscall(SYS_vmsplice, p[1], &iov, 1, 0), EPERM);
		close(p[0]); close(p[1]);
	}
	struct iovec l = { buf, 1 }, r = { buf + 1, 1 };
	errno = 0; expect_errno("process_vm_readv (self)", syscall(SYS_process_vm_readv, getpid(), &l, 1, &r, 1, 0), EPERM);
	struct { unsigned int bytes; int type; unsigned char h[128]; } fh = { 128, 0, {0} };
	int mnt;
	errno = 0; expect_errno("name_to_handle_at", syscall(SYS_name_to_handle_at, AT_FDCWD, "/", &fh, &mnt, 0), EPERM);
	errno = 0; expect_errno("clone3", syscall(SYS_clone3, NULL, 0), ENOSYS);

	pid_t t = fork();
	if (t == 0)
		do_traceme();
	waitpid(t, &st, 0);
	int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
	snprintf(d, sizeof d, "%s", code == 0 ? "allowed" : strerror(code));
	result(code == EPERM, "ptrace(PTRACE_TRACEME)", d);

	expect_signal("x32 syscall", do_x32_getpid, SIGSYS);

	printf("PROBE: jailed %d passed, %d failed\n", passed, failed);
	return failed ? 1 : 0;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc > 1 && strcmp(argv[1], "--jailed") == 0)
		return jailed_checks();
	if (getuid() != 0) {
		fprintf(stderr, "probe: run as root (it drops to uid 65534 for the second pass)\n");
		return 2;
	}
	run_all();
	lockdown_mode();
	rootfs_ownership();
	jail_exec_rejects();
	boot_sysctls();
	fflush(stdout);

	pid_t p = fork();
	if (p == 0) {
		who = "user";
		passed = failed = 0;
		if (setgroups(0, NULL) || setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534)) {
			result(0, "drop to uid 65534", strerror(errno));
			_exit(1);
		}
		// setuid clears dumpable, which makes /proc/self/* root-owned; restore it so the
		// /proc/self/mem check runs as the user instead of failing to open.
		prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
		run_all();
		unpriv_checks();
		surface_report();
		printf("PROBE: user %d passed, %d failed\n", passed, failed);
		fflush(stdout);
		_exit(failed > 255 ? 255 : failed);
	}
	int st;
	waitpid(p, &st, 0);
	int user_failed = WIFEXITED(st) ? WEXITSTATUS(st) : 1;
	printf("PROBE: root %d passed, %d failed\n", passed, failed);
	return (failed || user_failed) ? 1 : 0;
}
