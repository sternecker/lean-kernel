#!/usr/bin/env bash
# The seccomp filter Firecracker runs under: the release's own filter, tightened, compiled with the
# release's own seccompiler. Every launch passes it (--seccomp-filter): run.sh, test.sh, run-agent.sh, and
# the jail (jail-setup.sh builds a root-owned copy into /usr/local/lib/lean-agent).
#
#   scripts/seccomp-filter.sh [OUT.bpf]      default out/seccomp-filter.bpf; the edited JSON lands next to it
#   SECCOMP_SRC=<dir>                        where the release's seccomp-filter-<v>.json and seccompiler-bin-<v>
#                                            are (default bin/release-<v>-x86_64, from make deps)
#
# Changes from the shipped filter (docs/firecracker-review-v1.17.0.md, findings A and G):
#   - io_uring_setup / io_uring_enter / io_uring_register removed from every thread. seccomp sees only those
#     three entry syscalls; the opcodes in the submission ring (openat, socket, connect, unlinkat, ...) run
#     without any seccomp check, so a compromised VMM would get back everything the rest of the filter
#     denies, plus the io_uring kernel surface. Firecracker uses io_uring only for the Async block engine,
#     which is off by default and not used here.
#   - default_action kill_process instead of trap. With trap, a denied syscall runs Firecracker's SIGSYS
#     handler, which takes the logger and metrics locks before exiting; code already running in the process
#     can hold those locks and turn the kill into a hang. kill_process ends the process in the kernel.
# The result is deterministic for a given release: rerunning it rewrites the same bytes.
source "$(dirname "$0")/_env.sh"

out="${1:-$OUT/seccomp-filter.bpf}"
src="${SECCOMP_SRC:-$BIN/release-$FIRECRACKER_VERSION-x86_64}"
json="$src/seccomp-filter-$FIRECRACKER_VERSION-x86_64.json"
compiler="$src/seccompiler-bin-$FIRECRACKER_VERSION-x86_64"
[[ -f "$json" ]] || die "no $json; run make deps"
[[ -x "$compiler" ]] || die "no $compiler; run make deps"
edited="${out%.bpf}.json"

# Up to date when newer than its inputs and this script.
if [[ -f "$out" && -f "$edited" && "$out" -nt "$json" && "$out" -nt "$compiler" && "$out" -nt "$0" ]]; then
  echo "seccomp filter: $out (up to date)"
  exit 0
fi
mkdir -p "$(dirname "$out")"
python3 -I - "$json" "$edited.tmp" <<'EOF'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
j = json.load(open(src))
removed = 0
for thread, f in j.items():
    before = len(f["filter"])
    f["filter"] = [r for r in f["filter"] if not r["syscall"].startswith("io_uring_")]
    removed += before - len(f["filter"])
    if f.get("default_action") != "trap":
        print(f"warn: {thread} default_action is {f.get('default_action')!r}, not 'trap': the release changed; review the filter", file=sys.stderr)
    f["default_action"] = "kill_process"
if removed == 0:
    print("warn: the release filter has no io_uring rules any more; the removal is a no-op (drop it from the docs)", file=sys.stderr)
json.dump(j, open(dst, "w"), indent=2)
print(f"{removed} io_uring rules removed; default_action kill_process on {', '.join(j)}")
EOF
"$compiler" --target-arch x86_64 --input-file "$edited.tmp" --output-file "$out.tmp" \
  || { rm -f -- "$edited.tmp" "$out.tmp"; die "seccompiler failed on $edited.tmp"; }
mv -f -- "$edited.tmp" "$edited"
mv -f -- "$out.tmp" "$out"
echo "seccomp filter: $out (from $(basename "$json"); edited JSON: $edited)"
