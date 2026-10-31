# lean-kernel: minimal hardened Firecracker guest kernel.
# Every target is a thin wrapper over scripts/; run the script directly for options.

.PHONY: deps fetch config build check syscalls rootfs run test clean distclean

deps:
	@scripts/deps-check.sh

fetch:
	@scripts/fetch-kernel.sh

config:
	@scripts/configure.sh

build:
	@scripts/build.sh

check:
	@scripts/check.sh

syscalls:
	@scripts/syscalls.sh

rootfs:
	@scripts/mkrootfs.sh

run:
	@scripts/run.sh

test:
	@scripts/test.sh

clean:
	rm -rf out

distclean: clean
	rm -rf work bin
