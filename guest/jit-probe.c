// jit-probe: does the agent's syscall policy let a process make its OWN anonymous memory executable
// and run code it wrote there at runtime? That is the primitive every in-process JIT uses -- Bun's
// JavaScriptCore, a bun:ffi TinyCC compile, Python ctypes, V8, LuaJIT -- and it does NOT touch the
// filesystem or a memfd, so neither the `noexec` writable mounts nor `vm.memfd_noexec=2` cover it.
//
// This is a posture probe, not a cut. agent-selftest runs it to record, truthfully, that the gap is
// open: jail-exec allows mmap/mprotect with any prot (it has to -- Claude Code is itself a JIT), and
// no kernel option enforces userspace W^X. If a future change ever closes the gap, this probe starts
// failing and the selftest line flips, so the claim in the docs stays honest.
//
//   exit 0  -> executable anonymous memory obtained and agent-written code ran (W^X NOT enforced)
//   exit 1  -> blocked before the code could run (W^X enforced somewhere)
//   exit 2  -> probe could not set itself up (inconclusive; treat as a test error, not a result)
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void)
{
	// x86-64: mov eax, 0x5eeded ; ret  -- a function returning a value we can recognise.
	static const unsigned char code[] = { 0xb8, 0xed, 0xed, 0x5e, 0x00, 0xc3 };
	long pg = sysconf(_SC_PAGESIZE);
	if (pg <= 0)
		pg = 4096;

	// The honest JIT sequence: writable first, fill in code, then ask for execute. If a filter
	// denied anonymous PROT_EXEC up front we would also want to know, so try the direct W|X mmap too.
	void *m = mmap(NULL, (size_t)pg, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (m == MAP_FAILED) {
		perror("jit-probe: mmap rw");
		return 2;
	}
	memcpy(m, code, sizeof code);
	if (mprotect(m, (size_t)pg, PROT_READ | PROT_EXEC) != 0) {
		// Writable->executable was refused. Confirm a direct executable mapping is refused too,
		// then report "blocked" rather than guessing.
		perror("jit-probe: mprotect r-x (W^X appears enforced)");
		void *x = mmap(NULL, (size_t)pg, PROT_READ | PROT_WRITE | PROT_EXEC,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (x == MAP_FAILED)
			return 1;
		memcpy(x, code, sizeof code);
		if (((int (*)(void))x)() == 0x5eeded)
			return 0;   // W|X mapping worked even though mprotect didn't
		return 1;
	}
	int r = ((int (*)(void))m)();
	if (r != 0x5eeded) {
		fprintf(stderr, "jit-probe: ran but returned 0x%x, not 0x5eeded\n", r);
		return 2;
	}
	return 0;   // agent-written native code executed from anonymous memory
}
