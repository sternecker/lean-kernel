// Stands in for the real bash in tests/tool-shell-test.py: runs under the seccomp filter from
// guest/tool-shell.c built without MDWE, and prints one "ok"/"FAIL" line per check.
// Exit status is the number of failures.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#ifndef PR_GET_MDWE
#define PR_GET_MDWE 66
#endif

static int fails;

static void check(const char *name, int ok)
{
	printf("%s %s\n", ok ? "ok" : "FAIL", name);
	fails += !ok;
}

static int mmap_errno(int fd, int prot, int flags)
{
	void *p = mmap(NULL, 4096, prot, flags, fd, 0);
	if (p == MAP_FAILED)
		return errno;
	munmap(p, 4096);
	return 0;
}

int main(void)
{
	int fd = open("/proc/self/exe", O_RDONLY);
	int anon = MAP_PRIVATE | MAP_ANONYMOUS, priv = MAP_PRIVATE;

	// The test means nothing if the kernel's MDWE is what refuses these.
	check("MDWE is not set (the filter is tested alone)", prctl(PR_GET_MDWE, 0, 0, 0, 0) == 0);

	check("anon RWX mmap -> EPERM", mmap_errno(-1, PROT_READ | PROT_WRITE | PROT_EXEC, anon) == EPERM);
	check("anon RX mmap -> EPERM", mmap_errno(-1, PROT_READ | PROT_EXEC, anon) == EPERM);
	check("file-backed MAP_PRIVATE RWX mmap -> EPERM", mmap_errno(fd, PROT_READ | PROT_WRITE | PROT_EXEC, priv) == EPERM);
	check("file-backed W+X (no R) mmap -> EPERM", mmap_errno(fd, PROT_WRITE | PROT_EXEC, priv) == EPERM);

	void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, anon, -1, 0);
	check("anon RW mmap allowed", p != MAP_FAILED);
	if (p != MAP_FAILED) {
		check("mprotect RW -> RX -> EPERM", mprotect(p, 4096, PROT_READ | PROT_EXEC) == -1 && errno == EPERM);
		check("mprotect RW -> RWX -> EPERM", mprotect(p, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) == -1 && errno == EPERM);
		check("mprotect RW -> R allowed", mprotect(p, 4096, PROT_READ) == 0);
	}
	check("file-backed R+X mmap allowed (how the loader maps code)", mmap_errno(fd, PROT_READ | PROT_EXEC, priv) == 0);
	check("file-backed RW mmap allowed", mmap_errno(fd, PROT_READ | PROT_WRITE, priv) == 0);
	return fails;
}
