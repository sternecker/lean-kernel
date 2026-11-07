// jit-probe: can this process make memory it can write to executable and run code it put there? That is
// the primitive every in-process JIT uses -- Bun's JavaScriptCore, a bun:ffi TinyCC compile, Python
// ctypes, V8, LuaJIT -- and it does NOT touch the filesystem or a memfd, so neither the `noexec` writable
// mounts nor `vm.memfd_noexec=2` cover it.
//
// Three ways in are tried, because a policy that stops one and not the others stops nothing:
//   1. anonymous RW mapping, write code, mprotect to RX    (the honest JIT sequence)
//   2. anonymous RWX mapping in one mmap call               (no mprotect at all)
//   3. MAP_PRIVATE RWX mapping of a readable FILE, write code  (copy-on-write makes the page private
//      memory, so a filter that only looks at MAP_ANONYMOUS lets it through; the file can be anything
//      readable, here /proc/self/exe or /bin/true)
// Exit status is the posture, not which path worked (stderr says which):
//   0  -> executable memory obtained and probe-written code ran by at least one path (W^X NOT enforced)
//   1  -> every path was refused before the code could run (W^X enforced)
//   2  -> the probe could not set itself up (inconclusive; treat as a test error, not a result)
//
// `jit-probe --get-mdwe` instead prints prctl(PR_GET_MDWE) for this process (0: not set, 1: set) and
// exits 0, so a shell can check whether a tool shell's Memory-Deny-Write-Execute flag is in effect.
//
// agent-selftest runs it from the agent (expects 0: known gap, see HOWTO 9.5; jail-exec must allow
// mmap/mprotect with any prot because Claude Code is itself a JIT) and from a tool shell (expects 1:
// guest/tool-shell.c sets PR_SET_MDWE and a seccomp W^X filter before exec).
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#ifndef PR_GET_MDWE
#define PR_GET_MDWE 66
#endif

// x86-64: mov eax, 0x5eeded ; ret  -- a function returning a value we can recognise.
static const unsigned char code[] = { 0xb8, 0xed, 0xed, 0x5e, 0x00, 0xc3 };
#define MAGIC 0x5eeded

static int run(void *m)
{
	return ((int (*)(void))m)() == MAGIC;
}

int main(int argc, char **argv)
{
	if (argc > 1 && strcmp(argv[1], "--get-mdwe") == 0) {
		int v = prctl(PR_GET_MDWE, 0, 0, 0, 0);
		if (v < 0) {
			perror("jit-probe: PR_GET_MDWE");
			return 2;
		}
		printf("%d\n", v);
		return 0;
	}
	long pg = sysconf(_SC_PAGESIZE);
	if (pg <= 0)
		pg = 4096;
	int ran = 0, setup_failed = 0;

	// 1. RW then mprotect to RX.
	void *m = mmap(NULL, (size_t)pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (m == MAP_FAILED) {
		perror("jit-probe: mmap rw");
		setup_failed = 1;
	} else {
		memcpy(m, code, sizeof code);
		if (mprotect(m, (size_t)pg, PROT_READ | PROT_EXEC) == 0) {
			if (run(m)) {
				fprintf(stderr, "jit-probe: ran via anonymous RW + mprotect RX\n");
				ran = 1;
			}
		} else {
			perror("jit-probe: mprotect rx refused");
		}
	}
	// 2. RWX in one go.
	void *x = mmap(NULL, (size_t)pg, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (x != MAP_FAILED) {
		memcpy(x, code, sizeof code);
		if (run(x)) {
			fprintf(stderr, "jit-probe: ran via anonymous RWX mmap\n");
			ran = 1;
		}
	} else {
		perror("jit-probe: mmap anonymous rwx refused");
	}
	// 3. Private RWX mapping of a readable file: copy-on-write turns the page into private memory.
	int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		fd = open("/bin/true", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		perror("jit-probe: open a file to map");
		setup_failed = 1;
	} else {
		void *f = mmap(NULL, (size_t)pg, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0);
		if (f != MAP_FAILED) {
			memcpy(f, code, sizeof code);
			if (run(f)) {
				fprintf(stderr, "jit-probe: ran via MAP_PRIVATE RWX file mapping\n");
				ran = 1;
			}
		} else {
			perror("jit-probe: mmap file rwx refused");
		}
		close(fd);
	}
	if (ran)
		return 0;
	return setup_failed ? 2 : 1;
}
