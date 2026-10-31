// jail-exec: start the agent inside the guest as an unprivileged user under a seccomp filter.
// Usage: jail-exec UID COMMAND [ARGS...]
//
// The lean kernel compiles out what it can (io_uring, bpf, userfaultfd, SysV IPC, keys, ...).
// This filter covers what it can't: calls x86 forces on (perf_event_open), calls everything needs
// a sibling of (vmsplice next to splice), and root-only calls kept as defense in depth in case the
// agent ever holds a capability. Non-x86_64 and x32 syscalls kill the process.
// Allowlist later, once the agent runtime's syscall set is known; this is a denylist on purpose.
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

// Namespace flags for clone(): CLONE_NEWTIME, NEWNS, NEWCGROUP, NEWUTS, NEWIPC, NEWUSER, NEWPID, NEWNET.
#define NS_FLAGS 0x7E020080u
// Newer than the host glibc headers (from arch/x86/entry/syscalls/syscall_64.tbl, 6.18).
#ifndef SYS_open_tree_attr
#define SYS_open_tree_attr 467
#endif

static const int denied[] = {
	// The kernel can't cut these.
	SYS_perf_event_open, SYS_vmsplice,
	// Cross-process inspection and file handles.
	SYS_ptrace, SYS_process_vm_readv, SYS_process_vm_writev,
	SYS_name_to_handle_at, SYS_open_by_handle_at, SYS_fanotify_init,
	// Namespaces and mounts (root-only today; denied anyway).
	SYS_unshare, SYS_setns, SYS_mount, SYS_umount2, SYS_pivot_root, SYS_chroot,
	SYS_fsopen, SYS_fsconfig, SYS_fsmount, SYS_fspick, SYS_move_mount, SYS_open_tree,
	SYS_open_tree_attr, SYS_mount_setattr,
	// Host-ish administration (root-only today).
	SYS_swapon, SYS_swapoff, SYS_reboot, SYS_acct, SYS_settimeofday, SYS_clock_settime,
	SYS_clock_adjtime, SYS_sethostname, SYS_setdomainname, SYS_quotactl, SYS_quotactl_fd,
	SYS_syslog,
};

#define N_DENIED (sizeof denied / sizeof *denied)
#define ALLOW  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
#define EPERM_ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)

static int install_filter(void)
{
	struct sock_filter f[16 + 2 * N_DENIED];
	unsigned n = 0;

	f[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
	f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
	f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
	f[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
	// x32 syscall numbers have bit 30 set.
	f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1);
	f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
	for (unsigned i = 0; i < N_DENIED; i++) {
		f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, denied[i], 0, 1);
		f[n++] = (struct sock_filter)EPERM_;
	}
	// clone3 passes flags through a pointer seccomp can't read: ENOSYS makes glibc fall back to clone.
	f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone3, 0, 1);
	f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS);
	// clone with any namespace flag: EPERM. Low 32 bits of args[0] (little endian).
	f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone, 0, 3);
	f[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0]));
	f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, NS_FLAGS, 0, 1);
	f[n++] = (struct sock_filter)EPERM_;
	f[n++] = (struct sock_filter)ALLOW;

	struct sock_fprog prog = { .len = (unsigned short)n, .filter = f };
	return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
}

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "usage: jail-exec UID COMMAND [ARGS...]\n");
		return 127;
	}
	char *end;
	long uid = strtol(argv[1], &end, 10);
	if (*end || uid <= 0) {
		fprintf(stderr, "jail-exec: UID must be a positive number (never run the agent as root)\n");
		return 127;
	}
	if (setgroups(0, NULL) || setresgid((gid_t)uid, (gid_t)uid, (gid_t)uid) ||
	    setresuid((uid_t)uid, (uid_t)uid, (uid_t)uid)) {
		perror("jail-exec: drop privileges");
		return 127;
	}
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("jail-exec: no_new_privs");
		return 127;
	}
	if (install_filter()) {
		perror("jail-exec: seccomp");
		return 127;
	}
	execv(argv[2], argv + 2);
	perror("jail-exec: exec");
	return 127;
}
