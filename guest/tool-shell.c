// tool-shell: the agent's tool shell. Installed as /bin/bash in the agent image, with the real bash
// at /bin/bash.real. It loads a seccomp filter that refuses executable anonymous memory and making
// memory executable after the fact (W^X), then execs the real bash with the same arguments.
//
// Claude Code runs every Bash tool command through bash, so each tool shell, and everything it starts,
// inherits the filter: a tool shell can't run the Bun/JavaScriptCore runtime (so not `claude` with a
// NODE_OPTIONS or BUN_* preload, and not bun:ffi's TinyCC), nor any other in-process JIT. Claude Code's
// own process keeps its JIT (it can't run without one); that is the gap NOTES section 5 still records.
// With the writable mounts noexec (and /dev, /proc and /sys too), the only executable mappings left to
// a tool shell are files on the read-only root. Refused calls are logged (type=1326; syscall 9 mmap,
// 10 mprotect, 329 pkey_mprotect). init bind-mounts the real bash over this with AGENT_EXEC=1, the
// opt-in for workloads that build and run code.
//
// Filter: mmap with PROT_EXEC and MAP_ANONYMOUS -> EPERM; mprotect or pkey_mprotect with PROT_EXEC
// -> EPERM; non-x86_64 and x32 -> kill; everything else falls through to the filters already in place
// (jail-exec's allowlist). Writing to a PROT_EXEC file mapping is refused by the kernel (the root is
// read-only), writing a file and mapping it executable by noexec, and /proc/self/mem can't override
// page protections (PROC_MEM_NO_FORCE).
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

#define STMT(c, k) ((struct sock_filter)BPF_STMT((c), (k)))
#define JUMP(c, k, t, f) ((struct sock_filter)BPF_JUMP((c), (k), (t), (f)))
#define RET(v) STMT(BPF_RET | BPF_K, (v))
#define LOAD(field) STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, field))
#define EQ(k, t, f) JUMP(BPF_JMP | BPF_JEQ | BPF_K, (k), (t), (f))
#define SET(k, t, f) JUMP(BPF_JMP | BPF_JSET | BPF_K, (k), (t), (f))

int main(int argc, char **argv)
{
	(void)argc;
	struct sock_filter f[] = {
		LOAD(arch),
		EQ(AUDIT_ARCH_X86_64, 1, 0),
		RET(SECCOMP_RET_KILL_PROCESS),
		LOAD(nr),
		JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1),	// x32 numbers
		RET(SECCOMP_RET_KILL_PROCESS),
		// mmap: prot is args[2], flags args[3] (low 32 bits each)
		EQ(SYS_mmap, 0, 5),
		LOAD(args[2]),
		SET(PROT_EXEC, 0, 3),
		LOAD(args[3]),
		SET(MAP_ANONYMOUS, 0, 1),
		RET(SECCOMP_RET_ERRNO | EPERM),
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
