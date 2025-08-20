#!/usr/bin/env bash
set -euo pipefail

# Always:
#  1) locate all directories having env.hcl
#  2) run 'terragrunt plan' in each (fast/lightweight flags)
#  3) scan the rendered Terraform under .terragrunt-cache with Snyk IaC

: "${SNYK_SEVERITY:=medium}"       # low|medium|high|critical
: "${SNYK_ORG:=}"                  # optional
: "${SNYK_ADDITIONAL_ARGS:=}"      # e.g. "--report --sarif-file-output=iac.sarif"
: "${TG_PLAN_ARGS:=-lock=false -input=false -no-color}"  # tweak if needed

need() { command -v "$1" >/dev/null 2>&1 || { echo "$1 not found"; exit 1; }; }
need terragrunt
need snyk

# Ensure Snyk is authed (token env OR already authed)
if ! snyk config get api >/dev/null 2>&1; then
  if [ -n "${SNYK_TOKEN:-}" ]; then
    snyk auth "${SNYK_TOKEN}" >/dev/null
  else
    echo "Snyk CLI not authenticated. Run 'snyk auth' or set SNYK_TOKEN." >&2
    exit 1
  fi
fi

# Find all env.hcl directories. Prefer git (faster, respects repo root); fall back to find(1).
env_dirs=()
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  while IFS= read -r -d '' f; do
    d="$(dirname "$f")"
    # de-dupe
    seen=0
    for s in ${env_dirs+"${env_dirs[@]}"}; do [ "$s" = "$d" ] && seen=1 && break; done
    [ $seen -eq 0 ] && env_dirs+=("$d")
  done < <(git ls-files -z -- '*env.hcl')
else
  while IFS= read -r -d '' f; do
    d="$(dirname "$f")"
    seen=0
    for s in ${env_dirs+"${env_dirs[@]}"}; do [ "$s" = "$d" ] && seen=1 && break; done
    [ $seen -eq 0 ] && env_dirs+=("$d")
  done < <(find . -type f -name 'env.hcl' -print0 2>/dev/null || true)
fi

if [ "${#env_dirs[@]}" -eq 0 ]; then
  echo "No env.hcl found. Nothing to plan/scan."
  exit 0
fi

# Optionally keep IaC rules current (fast no-op if already updated)
if [ "${SNYK_UPDATE_RULES:-1}" = "1" ]; then
  snyk iac rules update >/dev/null || true
fi

# Helper: list cache subdirs that contain at least one .tf
cache_targets_for_dir() {
  dir="$1"
  [ -d "$dir/.terragrunt-cache" ] || return 0
  find "$dir/.terragrunt-cache" -type f -name '*.tf' -print0 2>/dev/null \
    | xargs -0 -I{} dirname "{}" 2>/dev/null \
    | sort -u
}

# 1) Run terragrunt plan in each env dir to populate cache (don’t fail the whole hook if one plan fails)
for d in "${env_dirs[@]}"; do
  echo "Planning in: $d"
  (
    cd "$d"
    # Best-effort plan to warm the cache; ignore non-zero to continue scanning others
    terragrunt plan ${TG_PLAN_ARGS} -out=/dev/null >/dev/null || true
  )
done

# 2) Gather scan targets from all caches
scan_targets=()
for d in "${env_dirs[@]}"; do
  while IFS= read -r target; do
    [ -d "$target" ] || continue
    present=0
    for t in ${scan_targets+"${scan_targets[@]}"}; do [ "$t" = "$target" ] && present=1 && break; done
    [ $present -eq 0 ] && scan_targets+=("$target")
  done <<EOF
$(cache_targets_for_dir "$d")
EOF
done

if [ "${#scan_targets[@]}" -eq 0 ]; then
  echo "No rendered Terraform found under .terragrunt-cache after planning."
  echo "Check credentials/backends or run a manual 'terragrunt plan' to verify."
  exit 0
fi

# 3) Snyk IaC scan each target directory
echo "Snyk IaC: scanning ${#scan_targets[@]} cache dir(s)..."
common_args=( "iac" "test" "--severity-threshold=${SNYK_SEVERITY}" )
[ -n "$SNYK_ORG" ] && common_args+=( "--org=${SNYK_ORG}" )

rc=0
for tgt in "${scan_targets[@]}"; do
  echo "→ $tgt"
  # shellcheck disable=SC2086
  if ! snyk "${common_args[@]}" ${SNYK_ADDITIONAL_ARGS} "$tgt"; then
    rc=1
  fi
done

exit $rc