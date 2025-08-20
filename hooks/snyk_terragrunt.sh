#!/usr/bin/env bash
set -euo pipefail

# Snyk IaC for Terragrunt:
# - Triggers on terragrunt.hcl changes.
# - Finds rendered Terraform under .terragrunt-cache and scans those dirs with Snyk.
# - Optional: TERRAGRUNT_SNYK_PLAN=1 to run a quick 'terragrunt plan' to populate cache.

: "${SNYK_SEVERITY:=medium}"      # low|medium|high|critical
: "${SNYK_ORG:=}"                 # Snyk org (optional)
: "${SNYK_ADDITIONAL_ARGS:=}"     # extra args, e.g. "--report --sarif-file-output=iac.sarif"
: "${TERRAGRUNT_SNYK_PLAN:=0}"    # 1 to attempt 'terragrunt plan' to populate cache (requires creds)

need() { command -v "$1" >/dev/null 2>&1 || { echo "$1 not found"; exit 1; }; }
need snyk
need terragrunt

# Ensure Snyk is authed (token env OR already authed)
if ! snyk config get api >/dev/null 2>&1; then
  if [ -n "${SNYK_TOKEN:-}" ]; then
    snyk auth "${SNYK_TOKEN}" >/dev/null
  else
    echo "Snyk CLI not authenticated. Run 'snyk auth' or set SNYK_TOKEN." >&2
    exit 1
  fi
fi

# Build list of terragrunt stack dirs from filenames
stack_dirs=()
for f in "$@"; do
  if [ -f "$f" ]; then
    d="$(cd "$(dirname "$f")" && pwd)"
    # dedupe
    seen=0
    for s in "${stack_dirs[@]}"; do [ "$s" = "$d" ] && seen=1 && break; done
    [ $seen -eq 0 ] && stack_dirs+=("$d")
  fi
done

[ ${#stack_dirs[@]} -eq 0 ] && { echo "No Terragrunt files to scan."; exit 0; }

# Optionally keep IaC rules current (fast no-op if already updated)
if [ "${SNYK_UPDATE_RULES:-1}" = "1" ]; then
  snyk iac rules update >/dev/null || true
fi

# Helper: find cache subdirs that actually contain Terraform (.tf)
find_cache_targets() {
  dir="$1"
  if [ -d "$dir/.terragrunt-cache" ]; then
    # Look one or two levels down; Terragrunt hashes module paths.
    # We only keep directories that contain at least one .tf file.
    find "$dir/.terragrunt-cache" -type f -name '*.tf' -print0 2>/dev/null \
    | xargs -0 -I{} dirname "{}" 2>/dev/null \
    | sort -u
  fi
}

# If allowed, try to populate cache via 'terragrunt plan' (quick, but needs creds)
populate_cache_if_needed() {
  dir="$1"
  if [ "$TERRAGRUNT_SNYK_PLAN" = "1" ]; then
    ( cd "$dir" && terragrunt plan -lock=false -out=/dev/null >/dev/null ) || true
  fi
}

# Collect scan targets
scan_targets=()
for sd in "${stack_dirs[@]}"; do
  # Optionally populate cache (no-op if disabled)
  populate_cache_if_needed "$sd"

  # Gather cache dirs that have .tf
  while IFS= read -r target; do
    [ -d "$target" ] || continue
    # de-dupe
    present=0
    for t in "${scan_targets[@]}"; do [ "$t" = "$target" ] && present=1 && break; done
    [ $present -eq 0 ] && scan_targets+=("$target")
  done <<EOF
$(find_cache_targets "$sd")
EOF
done

if [ ${#scan_targets[@]} -eq 0 ]; then
  echo "No rendered Terraform found under .terragrunt-cache for changed stacks."
  echo "Hints:"
  echo "  - Run 'terragrunt plan' locally to populate .terragrunt-cache, or"
  echo "  - Set TERRAGRUNT_SNYK_PLAN=1 to let the hook attempt a quick plan (requires creds), or"
  echo "  - Run Snyk IaC in CI against a planned JSON (outside pre-commit)."
  exit 0
fi

echo "Snyk IaC: scanning ${#scan_targets[@]} Terragrunt cache dir(s)..."

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