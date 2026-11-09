// tool-shell: the agent's tool shell. Installed as /bin/bash in the agent image, with the real bash
// at /bin/bash.real. It makes this process and everything it will ever start unable to create
// writable-and-executable memory or to make memory executable after the fact (W^X), then execs the
// real bash with the same arguments.
//
// Claude Code runs every Bash tool command through bash, so each tool shell, and everything it starts,
// inherits the policy: a tool shell can't run the Bun/JavaScriptCore runtime (so not `claude` with a
// NODE_OPTIONS or BUN_* preload, and not bun:ffi's TinyCC), nor any other in-process JIT. Claude Code's
// own process keeps its JIT (it can't run without one); that is the gap NOTES section 5 still records.
// With the writable mounts noexec (and /dev, /proc and /sys too), the only executable mappings left to
// a tool shell are files on the read-only root, mapped as the kernel loaded them. init bind-mounts the
// real bash over this with AGENT_EXEC=1, the opt-in for workloads that build and run code.
//
// Two layers, the first the one that matters:
//   1. prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN): the kernel's Memory-Deny-Write-Execute (6.3+).
//      Every new mapping that is writable and executable is refused, whatever backs it (anonymous,
//      a memfd, a MAP_PRIVATE copy-on-write mapping of a file), and no mapping may gain PROT_EXEC it
//      did not have (mprotect, pkey_mprotect, MAP_FIXED over an existing one). It is checked at the
//      VMA, not at the syscall, so there is no second entry point to forget. It cannot be turned off,
//      and without PR_MDWE_NO_INHERIT it is inherited across fork and exec.
//   2. a seccomp filter with the same intent, kept as the backstop: mmap with PROT_EXEC and either
//      MAP_ANONYMOUS or PROT_WRITE -> EPERM; mprotect or pkey_mprotect with PROT_EXEC -> EPERM;
//      non-x86_64 and x32 -> kill. Everything else falls through to jail-exec's allowlist. Before MDWE
//      this filter was the only layer, and it had a hole: a MAP_PRIVATE RWX mapping of any readable
//      file is not MAP_ANONYMOUS, so it passed, and copy-on-write made its pages private writable
//      executable memory. guest/jit-probe.c tries that path too now, and agent-selftest expects it refused.
// Refused calls: MDWE answers EACCES (not logged); the seccomp layer logs type=1326 (syscall 9 mmap,
// 10 mprotect, 329 pkey_mprotect). Writing to a PROT_EXEC file mapping is refused by the kernel (the
// root is read-only), writing a file and mapping it executable by noexec, and /proc/self/mem can't
// override page protections (PROC_MEM_NO_FORCE).
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef REAL_SHELL
#define REAL_SHELL "/bin/bash.real"
#endif
#ifndef SYS_pkey_mprotect
#define SYS_pkey_mprotect 329
#endif
// Newer than some libc headers (include/uapi/linux/prctl.h, 6.3+).
#ifndef PR_SET_MDWE
#define PR_SET_MDWE 65
#define PR_MDWE_REFUSE_EXEC_GAIN (1UL << 0)
#endif
#ifndef PR_GET_MDWE
#define PR_GET_MDWE 66
#endif

#define STMT(c, k) ((struct sock_filter)BPF_STMT((c), (k)))
#define JUMP(c, k, t, f) ((struct sock_filter)BPF_JUMP((c), (k), (t), (f)))
#define RET(v) STMT(BPF_RET | BPF_K, (v))
#define LOAD(field) STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, field))
#define EQ(k, t, f) JUMP(BPF_JMP | BPF_JEQ | BPF_K, (k), (t), (f))
#define SET(k, t, f) JUMP(BPF_JMP | BPF_JSET | BPF_K, (k), (t), (f))

int main(int argc, char **argv)
{
	(void)argc;
	// TOOL_SHELL_TEST_NO_MDWE is only for tests/tool-shell-test.py, which builds a copy without layer 1
	// so the seccomp filter is checked on its own. The shipped build (mkrootfs-agent.sh) never sets it.
#ifndef TOOL_SHELL_TEST_NO_MDWE
	// 1. MDWE first: from here on this process can't create W+X memory, and neither can bash or
	// anything bash runs. Verified by reading it back; a kernel without it (before 6.3) fails closed.
	if (prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0)) {
		perror("tool-shell: PR_SET_MDWE");
		return 127;
	}
	if (prctl(PR_GET_MDWE, 0, 0, 0, 0) != (int)PR_MDWE_REFUSE_EXEC_GAIN) {
		fprintf(stderr, "tool-shell: MDWE did not take effect\n");
		return 127;
	}
#endif
	// 2. The seccomp backstop.
	struct sock_filter f[] = {
		LOAD(arch),
		EQ(AUDIT_ARCH_X86_64, 1, 0),
		RET(SECCOMP_RET_KILL_PROCESS),
		LOAD(nr),
		JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1),	// x32 numbers
		RET(SECCOMP_RET_KILL_PROCESS),
		// mmap: prot is args[2], flags args[3] (low 32 bits each). PROT_EXEC with PROT_WRITE is
		// refused whatever the flags; PROT_EXEC with MAP_ANONYMOUS is refused whatever the prot.
		EQ(SYS_mmap, 0, 7),
		LOAD(args[2]),
		SET(PROT_EXEC, 0, 5),
		SET(PROT_WRITE, 2, 0),
		LOAD(args[3]),
		SET(MAP_ANONYMOUS, 0, 1),
		RET(SECCOMP_RET_ERRNO | EPERM),
		RET(SECCOMP_RET_ALLOW),
		// mprotect / pkey_mprotect: prot is args[2]
		EQ(SYS_mprotect, 1, 0),
		EQ(SYS_pkey_mprotect, 0, 3),
		LOAD(args[2]),
		SET(PROT_EXEC, 0, 1),
		RET(SECCOMP_RET_ERRNO | EPERM),
		RET(SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = { .len = sizeof f / sizeof *f, .filter = f };
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("tool-shell: no_new_privs");
		return 127;
	}
	if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_LOG, &prog)) {
		perror("tool-shell: seccomp");
		return 127;
	}
	execv(REAL_SHELL, argv);	// argv[0] as given: bash decides login behaviour from it
	perror("tool-shell: exec " REAL_SHELL);
	return 127;
}
