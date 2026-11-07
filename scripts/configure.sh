#!/usr/bin/env bash
# base config + lean.fragment (+ llvm.fragment unless LLVM=0, + vsock-only.fragment with VSOCK_ONLY=1)
# -> out/.config, then verify every fragment line survived Kconfig dependency resolution.
# When two fragments set the same option, the later one wins (as in merge_config.sh) and is what's checked.
# merge_config.sh warns and moves on when a dependency overrides a line; this script does not.
source "$(dirname "$0")/_env.sh"

[[ -d "$SRC" ]] || die "kernel source missing; run make fetch"
require_clang
mkdir -p "$OUT"

frags=("$ROOT/configs/lean.fragment")
[[ "$LLVM" == "1" ]] && frags+=("$ROOT/configs/llvm.fragment")
[[ "$VSOCK_ONLY" == "1" ]] && frags+=("$ROOT/configs/vsock-only.fragment")

note "merging $(basename "$BASE_CONFIG") + ${frags[*]##*/}"
( cd "$SRC" && KCONFIG_CONFIG="$OUT/.config" scripts/kconfig/merge_config.sh -m -Q -O "$OUT" "$ROOT/$BASE_CONFIG" "${frags[@]}" >/dev/null )
( cd "$SRC" && make -s "${MAKE_TOOLCHAIN[@]}" O="$OUT" olddefconfig )

# Verification: re-read each fragment line against the final .config.
# Every symbol this kernel's Kconfig defines: an is-not-set line naming anything else is a typo or a
# rename, so the cut it means to make silently doesn't happen. That fails, it doesn't warn.
declare -A ksym=()
while read -r sym; do ksym[$sym]=1; done < <(grep -rhoE '^[[:space:]]*(menu)?config[[:space:]]+[A-Z0-9_]+' --include='Kconfig*' "$SRC" | awk '{print $2}' | sort -u)
fail=0; warn=0
declare -A wanted=(); order=()
for f in "${frags[@]}"; do
  while IFS= read -r line; do
    if [[ "$line" =~ ^#\ (CONFIG_[A-Z0-9_]+)\ is\ not\ set$ ]]; then
      opt="${BASH_REMATCH[1]}"; want="n"
    elif [[ "$line" =~ ^(CONFIG_[A-Z0-9_]+)=(.*)$ ]]; then
      opt="${BASH_REMATCH[1]}"; want="${BASH_REMATCH[2]}"
    else
      continue
    fi
    [[ -v "wanted[$opt]" ]] || order+=("$opt")
    wanted[$opt]="$want"
  done < "$f"
done
check_opt() {
  local opt="$1" want="$2" got
  got="$(grep -E "^$opt=" "$OUT/.config" | cut -d= -f2- || true)"
  if [[ "$want" == "n" ]]; then
    if [[ "$got" == "y" || "$got" == "m" ]]; then
      echo "FAIL  $opt wanted off, final config has =$got"; fail=$((fail+1))
    elif [[ -z "$got" ]] && ! grep -q "^# $opt is not set" "$OUT/.config"; then
      if [[ -v "ksym[${opt#CONFIG_}]" ]]; then
        echo "warn  $opt not in final config: a dependency is off, so it can't be on (harmless for an is-not-set line)"; warn=$((warn+1))
      else
        echo "FAIL  $opt is not a Kconfig symbol in $KERNEL_VERSION (renamed or removed): find what replaced it and update the fragment"; fail=$((fail+1))
      fi
    fi
  else
    if [[ "$got" != "$want" ]]; then
      echo "FAIL  $opt wanted $want, final config has ${got:-<absent>}"; fail=$((fail+1))
    fi
  fi
}
for opt in "${order[@]}"; do check_opt "$opt" "${wanted[$opt]}"; done

total=$(grep -cE "^CONFIG_[A-Z0-9_]+=(y|m)" "$OUT/.config")
base_total=$(grep -cE "^CONFIG_[A-Z0-9_]+=(y|m)" "$ROOT/$BASE_CONFIG")
echo "enabled options: base $base_total -> lean $total"
echo "verification: $fail failed, $warn warnings"
if [[ $fail -gt 0 && "${ALLOW_DRIFT:-0}" != "1" ]]; then
  die "fragment lines did not take effect (FAIL lines above): a Kconfig dependency overrode them, or the symbol doesn't exist. Fix the fragment (add the dependency, rename, or drop the line and record why). ALLOW_DRIFT=1 to continue anyway."
fi
profile="lean"; [[ "$VSOCK_ONLY" == "1" ]] && profile="lean-vsock"
cp "$OUT/.config" "$OUT/$profile-$KERNEL_VERSION.config"
echo "config: $OUT/.config"
