# lean-kernel: minimal hardened Firecracker guest kernel.
# Every target is a thin wrapper over scripts/; run the script directly for options.

.PHONY: deps fetch config build check syscalls rootfs run test agent-rootfs agent agent-test clean distclean

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

agent-rootfs:
	@scripts/mkrootfs-agent.sh

# Claude Code in a VM; see scripts/run-agent.sh (TASK='...' for headless).
agent:
	@scripts/run-agent.sh

# The agent VM's hardening, from inside the real agent image; no Claude Code, no tokens.
agent-test:
	@AGENT_SELFTEST=1 scripts/run-agent.sh

clean:
	rm -rf out

distclean: clean
	rm -rf work bin
