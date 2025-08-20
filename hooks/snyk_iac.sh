#!/usr/bin/env bash
set -euo pipefail

# Pre-commit hook: run Snyk IaC test on changed Terraform/Terragrunt files.
# Requirements:
#   - SNYK_TOKEN set (or you are already authenticated via `snyk auth`)
#   - snyk CLI installed: https://docs.snyk.io/snyk-cli/install-the-snyk-cli
#   - Optional: terragrunt installed if you also use the fmt hook

# Config via env vars:
: "${SNYK_SEVERITY:=medium}"     # low|medium|high|critical
: "${SNYK_ORG:=}"                # set if you need to target a specific org
: "${SNYK_ADDITIONAL_ARGS:=}"    # e.g., "--scan=resource-changes --report"

if ! command -v snyk >/dev/null 2>&1; then
  echo "snyk CLI not found. Install from https://docs.snyk.io/snyk-cli."
  exit 1
fi

# Ensure auth (either token env var or existing auth)
if ! snyk config get api > /dev/null 2>&1; then
  if [[ -n "${SNYK_TOKEN:-}" ]]; then
    snyk auth "${SNYK_TOKEN}" >/dev/null
  else
    echo "Snyk CLI not authenticated. Run 'snyk auth' or set SNYK_TOKEN."
    exit 1
  fi
fi

# Filter to files that still exist and are relevant to IaC scans
is_iac() {
  case "$1" in
    *.tf|*.tfvars|*.hcl|*.hcl.json) return 0 ;;
    *) return 1 ;;
  esac
}

mapfile -t changed_files < <(
  for f in "$@"; do
    [[ -f "$f" ]] && is_iac "$f" && echo "$f"
  done | sort -u
)

if [[ ${#changed_files[@]} -eq 0 ]]; then
  echo "No Terraform/Terragrunt files to scan."
  exit 0
fi

# Build the argument list. Snyk can take many files at once; we’ll chunk to be safe.
common_args=( "iac" "test" "--severity-threshold=${SNYK_SEVERITY}" )
[[ -n "${SNYK_ORG}" ]] && common_args+=( "--org=${SNYK_ORG}" )

# Exclude common noisy paths
ignore_patterns=( ".terragrunt-cache" ".terraform" )

filter_out_noise() {
  while IFS= read -r p; do
    skip=0
    for pat in "${ignore_patterns[@]}"; do
      if [[ "$p" == *"/${pat}/"* ]] || [[ "$p" == "${pat}"* ]]; then
        skip=1; break
      fi
    done
    [[ $skip -eq 0 ]] && echo "$p"
  done
}

mapfile -t targets < <(printf '%s\n' "${changed_files[@]}" | filter_out_noise)

if [[ ${#targets[@]} -eq 0 ]]; then
  echo "All changes are in ignored paths; nothing to scan."
  exit 0
fi

# Optionally keep rules up to date (no-op if already latest). Skip on CI if you prefer speed.
if [[ "${SNYK_UPDATE_RULES:-1}" == "1" ]]; then
  snyk iac rules update >/dev/null || true
fi

echo "Running Snyk IaC on ${#targets[@]} file(s)..."
# Chunk to avoid very long command lines
chunk_size=50
i=0
rc=0
while [[ $i -lt ${#targets[@]} ]]; do
  chunk=( "${targets[@]:$i:$chunk_size}" )
  # shellcheck disable=SC2086
  if ! snyk "${common_args[@]}" ${SNYK_ADDITIONAL_ARGS} "${chunk[@]}"; then
    rc=1
  fi
  i=$(( i + chunk_size ))
done

exit $rc