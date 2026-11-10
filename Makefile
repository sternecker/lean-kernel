# lean-kernel: minimal hardened Firecracker guest kernel.
# Every target is a thin wrapper over scripts/; run the script directly for options.

.PHONY: all version distro deps fetch config build check syscalls rootfs run test agent-rootfs agent agent-test sbom clean distclean

# Every step that needs no input and spends no tokens, in order; see scripts/all.sh (--vsock, --no-agent).
all:
	@scripts/all.sh

# The AI JAIL's version, the commit, and every pin in VERSION; paste it into a bug or security report.
version:
	@scripts/version.sh

# Which distro family (debian/rhel) the scripts detected; every target stops on an unsupported host.
distro:
	@scripts/distro-check.sh

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

# SPDX + CycloneDX SBOM of the agent image (needs syft); see scripts/sbom.sh. Run after agent-rootfs.
sbom:
	@scripts/sbom.sh

clean:
	rm -rf out

distclean: clean
	rm -rf work bin
