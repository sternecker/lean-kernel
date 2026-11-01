// jail-exec: start the agent inside the guest as an unprivileged user, confined by Landlock and a
// seccomp allowlist.
//
// Usage: jail-exec [--rw PATH]... [--connect PORT]... [--bind PORT]... [--vsock] UID COMMAND [ARGS...]
//   --rw PATH       Landlock: full access beneath PATH. Everything else is read and execute only,
//                   except /dev (read, write, device ioctls: terminals, /dev/null).
//   --connect PORT  Landlock: TCP connect to PORT allowed. No other TCP connects.
//   --bind PORT     Landlock: TCP bind/listen on PORT allowed. No other TCP binds.
//   --vsock         seccomp: allow AF_VSOCK sockets (the host bridge needs them, the agent doesn't).
//
// Steps, each failing closed (exit 127):
//   1. drop to UID (1..65534), verify every id changed and root can't be regained
//   2. no_new_privs
//   3. Landlock (ABI >= 6 required): the filesystem and TCP rules above, plus scoping, so the agent
//      can't signal or reach abstract unix sockets of processes outside its own domain (init, socat)
//   4. close every inherited fd above 2
//   5. seccomp: non-x86_64 and x32 calls kill the process; the explicit denylist returns EPERM;
//      clone with namespace flags EPERM; clone3 ENOSYS (glibc falls back to clone); socket() only
//      for AF_UNIX/AF_INET/AF_INET6 (+AF_VSOCK with --vsock); then the allowlist; anything else
//      returns ENOSYS. Refused calls are logged to the kernel log (SECCOMP_FILTER_FLAG_LOG,
//      "type=1326"; root can read it, the agent can't: dmesg_restrict).
//
// The allowlist is what Claude Code, bash, busybox and socat were seen to use (strace, from outside
// the jail: STRACE=1 make agent-rootfs, AGENT_STRACE=1 make agent), plus close relatives of those
// calls that ordinary userspace uses. To find a missing one, run the agent and grep dmesg for
// type=1326; the syscall number is in syscall=N.
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>

// Namespace flags for clone(): CLONE_NEWTIME, NEWNS, NEWCGROUP, NEWUTS, NEWIPC, NEWUSER, NEWPID, NEWNET.
#define NS_FLAGS 0x7E020080u
// Newer than some glibc headers (from arch/x86/entry/syscalls/syscall_64.tbl, 6.18).
#ifndef SYS_open_tree_attr
#define SYS_open_tree_attr 467
#endif
#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif

// EPERM, checked first: an explicit "no" for calls the kernel can't cut, cross-process access, and
// root-only administration kept as defense in depth in case the agent ever holds a capability.
static const int denied[] = {
	SYS_perf_event_open, SYS_vmsplice,
	SYS_ptrace, SYS_process_vm_readv, SYS_process_vm_writev, SYS_pidfd_getfd, SYS_process_madvise,
	SYS_kcmp, SYS_name_to_handle_at, SYS_open_by_handle_at, SYS_fanotify_init,
	SYS_unshare, SYS_setns, SYS_mount, SYS_umount2, SYS_pivot_root, SYS_chroot,
	SYS_fsopen, SYS_fsconfig, SYS_fsmount, SYS_fspick, SYS_move_mount, SYS_open_tree,
	SYS_open_tree_attr, SYS_mount_setattr,
	SYS_swapon, SYS_swapoff, SYS_reboot, SYS_acct, SYS_settimeofday, SYS_clock_settime,
	SYS_clock_adjtime, SYS_adjtimex, SYS_sethostname, SYS_setdomainname, SYS_quotactl,
	SYS_quotactl_fd, SYS_syslog,
};

// ALLOW. clone, clone3 and socket are handled separately and must not appear here.
static const int allowed[] = {
	// Seen in traces of Claude Code, bash, busybox and socat.
	SYS_accept, SYS_access, SYS_arch_prctl, SYS_bind, SYS_brk, SYS_chdir, SYS_chmod, SYS_chown,
	SYS_clock_nanosleep, SYS_close, SYS_close_range, SYS_connect, SYS_copy_file_range, SYS_dup,
	SYS_dup2, SYS_epoll_create1, SYS_epoll_ctl, SYS_epoll_pwait2, SYS_eventfd2, SYS_execve,
	SYS_fchmod, SYS_fcntl, SYS_fstat, SYS_fsync, SYS_ftruncate, SYS_futex, SYS_getcwd,
	SYS_getdents64, SYS_getegid, SYS_geteuid, SYS_getgid, SYS_getgroups, SYS_getpeername,
	SYS_getpgrp, SYS_getpid, SYS_getppid, SYS_getrandom, SYS_getresgid, SYS_getresuid,
	SYS_getrusage, SYS_getsockname, SYS_gettid, SYS_getuid, SYS_inotify_add_watch,
	SYS_inotify_init1, SYS_inotify_rm_watch, SYS_ioctl, SYS_kill, SYS_listen, SYS_lseek,
	SYS_madvise, SYS_mkdir, SYS_mmap, SYS_mprotect, SYS_munmap, SYS_newfstatat, SYS_open,
	SYS_openat, SYS_pidfd_open, SYS_pipe2, SYS_poll, SYS_prctl, SYS_pread64, SYS_preadv2,
	SYS_prlimit64, SYS_pselect6, SYS_pwrite64, SYS_read, SYS_readlink, SYS_readlinkat,
	SYS_recvfrom, SYS_recvmsg, SYS_rename, SYS_restart_syscall, SYS_rmdir, SYS_rseq,
	SYS_rt_sigaction, SYS_rt_sigprocmask, SYS_rt_sigreturn, SYS_sched_getaffinity,
	SYS_sched_yield, SYS_seccomp, SYS_sendfile, SYS_sendmmsg, SYS_sendto, SYS_set_robust_list,
	SYS_set_tid_address, SYS_setgid, SYS_setgroups, SYS_setpgid, SYS_setresgid, SYS_setresuid,
	SYS_setsid, SYS_setsockopt, SYS_setuid, SYS_shutdown, SYS_sigaltstack, SYS_socketpair,
	SYS_stat, SYS_statx, SYS_sysinfo, SYS_tgkill, SYS_uname, SYS_unlink, SYS_unlinkat,
	SYS_utimensat, SYS_vfork, SYS_wait4, SYS_write,
	// Close relatives: the same operation through another entry point that libc or tools pick
	// depending on version and arguments.
	SYS_exit, SYS_exit_group, SYS_nanosleep, SYS_clock_gettime, SYS_clock_getres,
	SYS_gettimeofday, SYS_time, SYS_getpgid, SYS_getsid, SYS_getpriority, SYS_setpriority,
	SYS_sched_getparam, SYS_sched_getscheduler, SYS_sched_get_priority_max,
	SYS_sched_get_priority_min, SYS_getcpu, SYS_mremap, SYS_msync, SYS_mincore, SYS_membarrier,
	SYS_readv, SYS_writev, SYS_preadv, SYS_pwritev, SYS_pwritev2, SYS_ppoll, SYS_select,
	SYS_epoll_wait, SYS_epoll_pwait, SYS_epoll_create, SYS_dup3, SYS_pipe, SYS_fchdir,
	SYS_fchown, SYS_lchown, SYS_fchownat, SYS_fchmodat, SYS_fchmodat2, SYS_mkdirat,
	SYS_renameat, SYS_renameat2, SYS_link, SYS_linkat, SYS_symlink, SYS_symlinkat,
	SYS_faccessat, SYS_faccessat2, SYS_lstat, SYS_fstatfs, SYS_statfs, SYS_truncate,
	SYS_fdatasync, SYS_fallocate, SYS_flock, SYS_fadvise64, SYS_readahead, SYS_umask,
	SYS_getxattr, SYS_lgetxattr, SYS_fgetxattr, SYS_listxattr, SYS_llistxattr, SYS_flistxattr,
	SYS_alarm, SYS_getitimer, SYS_setitimer, SYS_timer_create, SYS_timer_settime,
	SYS_timer_gettime, SYS_timer_getoverrun, SYS_timer_delete, SYS_timerfd_create,
	SYS_timerfd_settime, SYS_timerfd_gettime, SYS_signalfd4, SYS_rt_sigsuspend,
	SYS_rt_sigtimedwait, SYS_rt_sigpending, SYS_tkill, SYS_pidfd_send_signal, SYS_waitid,
	SYS_accept4, SYS_getsockopt, SYS_sendmsg, SYS_recvmmsg, SYS_splice, SYS_tee,
	SYS_capget, SYS_getdents, SYS_futex_waitv, SYS_get_robust_list, SYS_execveat,
	SYS_landlock_create_ruleset, SYS_landlock_add_rule, SYS_landlock_restrict_self,
};

#define N(a) (sizeof(a) / sizeof *(a))
#define STMT(c, k) ((struct sock_filter)BPF_STMT((c), (k)))
#define JUMP(c, k, t, f) ((struct sock_filter)BPF_JUMP((c), (k), (t), (f)))
#define RET(v) STMT(BPF_RET | BPF_K, (v))
#define LOAD(field) STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, field))

static int install_filter(int vsock)
{
	struct sock_filter f[32 + 2 * N(denied) + 2 * N(allowed)];
	unsigned n = 0;

	f[n++] = LOAD(arch);
	f[n++] = JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
	f[n++] = RET(SECCOMP_RET_KILL_PROCESS);
	f[n++] = LOAD(nr);
	// x32 syscall numbers have bit 30 set.
	f[n++] = JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1);
	f[n++] = RET(SECCOMP_RET_KILL_PROCESS);
	for (unsigned i = 0; i < N(denied); i++) {
		f[n++] = JUMP(BPF_JMP | BPF_JEQ | BPF_K, denied[i], 0, 1);
		f[n++] = RET(SECCOMP_RET_ERRNO | EPERM);
	}
	// clone3 passes flags through a pointer seccomp can't read: ENOSYS makes glibc fall back to clone.
	f[n++] = JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone3, 0, 1);
	f[n++] = RET(SECCOMP_RET_ERRNO | ENOSYS);
	// clone: EPERM with any namespace flag (low 32 bits of args[0], little endian), else allow.
	f[n++] = JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone, 0, 4);
	f[n++] = LOAD(args[0]);
	f[n++] = JUMP(BPF_JMP | BPF_JSET | BPF_K, NS_FLAGS, 0, 1);
	f[n++] = RET(SECCOMP_RET_ERRNO | EPERM);
	f[n++] = RET(SECCOMP_RET_ALLOW);
	// socket: allow listed address families only (domain is args[0]).
	f[n++] = JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket, 0, 7);
	f[n++] = LOAD(args[0]);
	f[n++] = JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 3, 0);
	f[n++] = JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 2, 0);
	f[n++] = JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET6, 1, 0);
	f[n++] = JUMP(BPF_JMP | BPF_JEQ | BPF_K, vsock ? AF_VSOCK : AF_UNIX, 0, 1);
	f[n++] = RET(SECCOMP_RET_ALLOW);
	f[n++] = RET(SECCOMP_RET_ERRNO | EPERM);
	for (unsigned i = 0; i < N(allowed); i++) {
		f[n++] = JUMP(BPF_JMP | BPF_JEQ | BPF_K, allowed[i], 0, 1);
		f[n++] = RET(SECCOMP_RET_ALLOW);
	}
	f[n++] = RET(SECCOMP_RET_ERRNO | ENOSYS);

	struct sock_fprog prog = { .len = (unsigned short)n, .filter = f };
	return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_LOG, &prog);
}

#define FS_READ (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR)
#define FS_ALL (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE | FS_READ | \
		LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE | \
		LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG | \
		LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
		LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_TRUNCATE | \
		LANDLOCK_ACCESS_FS_IOCTL_DEV)
// What --rw grants: everything except creating device nodes.
#define FS_RW (FS_ALL & ~(LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_BLOCK))

static int add_path(int ruleset, const char *path, __u64 access)
{
	struct landlock_path_beneath_attr pb = { .allowed_access = access };
	pb.parent_fd = open(path, O_PATH | O_CLOEXEC);
	if (pb.parent_fd < 0) {
		fprintf(stderr, "jail-exec: landlock: %s: %s\n", path, strerror(errno));
		return -1;
	}
	int rc = (int)syscall(SYS_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
	if (rc)
		fprintf(stderr, "jail-exec: landlock: rule for %s: %s\n", path, strerror(errno));
	close(pb.parent_fd);
	return rc;
}

static int add_port(int ruleset, long port, __u64 access)
{
	struct landlock_net_port_attr np = { .allowed_access = access, .port = (__u64)port };
	int rc = (int)syscall(SYS_landlock_add_rule, ruleset, LANDLOCK_RULE_NET_PORT, &np, 0);
	if (rc)
		fprintf(stderr, "jail-exec: landlock: rule for port %ld: %s\n", port, strerror(errno));
	return rc;
}

#define MAX_RULES 16
struct policy {
	const char *rw[MAX_RULES];
	long connect[MAX_RULES], bind[MAX_RULES];
	int nrw, nconnect, nbind, vsock;
};

static int apply_landlock(const struct policy *p)
{
	int abi = (int)syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 6) {
		fprintf(stderr, "jail-exec: landlock ABI %d, need 6 or later (filesystem, TCP and scoping)\n", abi);
		return -1;
	}
	struct landlock_ruleset_attr ra = {
		.handled_access_fs = FS_ALL,
		.handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP,
		.scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL,
	};
	int rs = (int)syscall(SYS_landlock_create_ruleset, &ra, sizeof ra, 0);
	if (rs < 0) {
		perror("jail-exec: landlock_create_ruleset");
		return -1;
	}
	int bad = add_path(rs, "/", FS_READ | LANDLOCK_ACCESS_FS_EXECUTE) ||
		  add_path(rs, "/dev", FS_READ | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_IOCTL_DEV);
	for (int i = 0; !bad && i < p->nrw; i++)
		bad = add_path(rs, p->rw[i], FS_RW);
	for (int i = 0; !bad && i < p->nconnect; i++)
		bad = add_port(rs, p->connect[i], LANDLOCK_ACCESS_NET_CONNECT_TCP);
	for (int i = 0; !bad && i < p->nbind; i++)
		bad = add_port(rs, p->bind[i], LANDLOCK_ACCESS_NET_BIND_TCP);
	// ABI 7: also log denials after exec (the default only logs the restricting program's own).
	__u32 flags = abi >= 7 ? LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON : 0;
	if (!bad && syscall(SYS_landlock_restrict_self, rs, flags)) {
		perror("jail-exec: landlock_restrict_self");
		bad = 1;
	}
	close(rs);
	return bad ? -1 : 0;
}

// Digits only (no sign, space or leading zero) in [lo, hi], else -1.
static long parse_num(const char *s, long lo, long hi)
{
	if (*s < '1' || *s > '9')
		return -1;
	char *end;
	errno = 0;
	long v = strtol(s, &end, 10);
	return (errno || *end || v < lo || v > hi) ? -1 : v;
}

static int usage(void)
{
	fprintf(stderr, "usage: jail-exec [--rw PATH]... [--connect PORT]... [--bind PORT]... [--vsock] UID COMMAND [ARGS...]\n");
	return 127;
}

int main(int argc, char **argv)
{
	struct policy p = { 0 };
	int i = 1;
	for (; i < argc && strncmp(argv[i], "--", 2) == 0; i++) {
		const char *o = argv[i];
		if (strcmp(o, "--vsock") == 0) {
			p.vsock = 1;
			continue;
		}
		if (i + 1 >= argc)
			return usage();
		const char *v = argv[++i];
		long port = strcmp(o, "--rw") ? parse_num(v, 1, 65535) : 0;
		if (strcmp(o, "--rw") == 0 && p.nrw < MAX_RULES && v[0] == '/') {
			p.rw[p.nrw++] = v;
		} else if (strcmp(o, "--connect") == 0 && port > 0 && p.nconnect < MAX_RULES) {
			p.connect[p.nconnect++] = port;
		} else if (strcmp(o, "--bind") == 0 && port > 0 && p.nbind < MAX_RULES) {
			p.bind[p.nbind++] = port;
		} else {
			fprintf(stderr, "jail-exec: bad option %s %s\n", o, v);
			return usage();
		}
	}
	if (argc - i < 2)
		return usage();

	// 1. Privilege drop. A plain strtol + cast once let 4294967296 wrap to uid 0 and 4294967295
	// become (uid_t)-1, which setresuid treats as "leave unchanged": either way the agent kept root.
	long v = parse_num(argv[i], 1, 65534);
	if (v < 0) {
		fprintf(stderr, "jail-exec: UID must be a number from 1 to 65534 (never run the agent as root)\n");
		return 127;
	}
	uid_t uid = (uid_t)v;
	gid_t gid = (gid_t)v;
	if (setgroups(0, NULL) || setresgid(gid, gid, gid) || setresuid(uid, uid, uid)) {
		perror("jail-exec: drop privileges");
		return 127;
	}
	uid_t ru, eu, su;
	gid_t rg, eg, sg;
	if (getresuid(&ru, &eu, &su) || getresgid(&rg, &eg, &sg) ||
	    ru != uid || eu != uid || su != uid || rg != gid || eg != gid || sg != gid ||
	    getgroups(0, NULL) != 0) {
		fprintf(stderr, "jail-exec: privilege drop did not take effect\n");
		return 127;
	}
	if (setresuid(0, 0, 0) == 0 || setresgid(0, 0, 0) == 0) {
		fprintf(stderr, "jail-exec: could regain root after dropping privileges\n");
		return 127;
	}
	// 2.
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("jail-exec: no_new_privs");
		return 127;
	}
	// 3.
	if (apply_landlock(&p))
		return 127;
	// 4. Nothing but stdin/stdout/stderr crosses into the agent.
	if (syscall(SYS_close_range, 3, ~0U, 0)) {
		perror("jail-exec: close_range");
		return 127;
	}
	// 5.
	if (install_filter(p.vsock)) {
		perror("jail-exec: seccomp");
		return 127;
	}
	execv(argv[i + 1], argv + i + 1);
	perror("jail-exec: exec");
	return 127;
}
