#!/usr/bin/env bash
set -euo pipefail

: "${SNYK_SEVERITY:=medium}"     # low|medium|high|critical
: "${SNYK_ORG:=}"                # set if you need to target a specific org
: "${SNYK_ADDITIONAL_ARGS:=}"    # e.g., "--scan=resource-changes --report"

if ! command -v snyk >/dev/null 2>&1; then
  echo "snyk CLI not found. Install from https://docs.snyk.io/snyk-cli."
  exit 1
fi

# Ensure auth (either token env var or existing auth)
if ! snyk config get api >/dev/null 2>&1; then
  if [ -n "${SNYK_TOKEN:-}" ]; then
    snyk auth "${SNYK_TOKEN}" >/dev/null
  else
    echo "Snyk CLI not authenticated. Run 'snyk auth' or set SNYK_TOKEN."
    exit 1
  fi
fi

# filters
is_iac() {
  case "$1" in
    *.tf|*.tfvars|*.hcl|*.hcl.json) return 0 ;;
    *) return 1 ;;
  esac
}

ignore_patterns=( ".terragrunt-cache" ".terraform" )

in_ignored_path() {
  _p="$1"
  for pat in "${ignore_patterns[@]}"; do
    case "$_p" in
      *"/$pat/"*|"$pat"*) return 0 ;;
    esac
  done
  return 1
}

# Build list of targets from args (no mapfile)
targets=()
for f in "$@"; do
  if [ -f "$f" ] && is_iac "$f" && ! in_ignored_path "$f"; then
    targets+=("$f")
  fi
done

# Deduplicate while preserving order
deduped=()
seen=""
for f in "${targets[@]}"; do
  case " $seen " in
    *" $f "*) : ;;
    *) deduped+=("$f"); seen="$seen $f" ;;
  esac
done
targets=("${deduped[@]}")

if [ ${#targets[@]} -eq 0 ]; then
  echo "No Terraform/Terragrunt files to scan."
  exit 0
fi

# Optionally update rules
if [ "${SNYK_UPDATE_RULES:-1}" = "1" ]; then
  snyk iac rules update >/dev/null || true
fi

echo "Running Snyk IaC on ${#targets[@]} file(s)..."

common_args=( "iac" "test" "--severity-threshold=${SNYK_SEVERITY}" )
[ -n "${SNYK_ORG}" ] && common_args+=( "--org=${SNYK_ORG}" )

# Chunk to avoid very long commands
chunk_size=50
i=0
rc=0
total=${#targets[@]}
while [ $i -lt $total ]; do
  chunk=( "${targets[@]:$i:$chunk_size}" )
  # shellcheck disable=SC2086
  if ! snyk "${common_args[@]}" ${SNYK_ADDITIONAL_ARGS} "${chunk[@]}"; then
    rc=1
  fi
  i=$(( i + chunk_size ))
done

exit $rc