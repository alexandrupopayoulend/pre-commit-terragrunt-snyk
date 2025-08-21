#!/usr/bin/env bash
# Minimal, portable flow:
#   - find dirs with env.hcl
#   - in each: terragrunt plan -out=tf.plan (with flags)
#              terraform show -json tf.plan > tfplan.json
#   - snyk iac test --scan=planned-values tfplan.json (all)

set -euo pipefail

: "${TF_PLAN_ARGS:=-input=false -no-color -lock=false -refresh=false}"
: "${SNYK_SEVERITY:=medium}"            # low|medium|high|critical
: "${SNYK_ORG:=}"                       # optional
: "${SNYK_ADDITIONAL_ARGS:=}"           # e.g. "--report --sarif-file-output=iac.sarif"
: "${SNYK_UPDATE_RULES:=1}"             # set 0 to skip snyk rules update

need() { command -v "$1" >/dev/null 2>&1 || { echo "$1 not found"; exit 1; }; }
need terragrunt
need terraform
need snyk

# Non-interactive Terraform
export TF_INPUT=0
export TF_IN_AUTOMATION=1

# If a token is present, auth Snyk; otherwise rely on prior auth
if ! snyk config get api >/dev/null 2>&1; then
  if [ -n "${SNYK_TOKEN:-}" ]; then
    snyk auth "${SNYK_TOKEN}" >/dev/null
  else
    echo "Snyk CLI not authenticated. Run 'snyk auth' or set SNYK_TOKEN." >&2
    exit 1
  fi
fi

# Move to repo root if inside git (makes discovery predictable)
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  cd "$(git rev-parse --show-toplevel)"
fi

# Discover env roots (dirs containing env.hcl)
env_dirs=()
# Prefer git (fast, respects ignores), fall back to find
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  while IFS= read -r -d '' f; do
    d="$(dirname "$f")"
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

# (Optional) keep Snyk IaC rules current
if [ "$SNYK_UPDATE_RULES" = "1" ]; then
  snyk iac rules update >/dev/null || true
fi

plan_jsons=()

# For each env root: plan -> show -> collect tfplan.json (continue on failures)
for d in "${env_dirs[@]}"; do
  echo "=== Planning in: $d"
  (
    cd "$d"

    # Remove stale artifacts to avoid confusion
    rm -f tf.plan tfplan.json || true

    # Best-effort plan; don't fail the whole hook if this one fails
    set +e
    terragrunt plan ${TF_PLAN_ARGS} -out=tf.plan
    rc=$?
    set -e

    if [ $rc -ne 0 ]; then
      echo "WARN: terragrunt plan failed in $d; skipping."
      exit 0
    fi

    # Convert to JSON (must run from same dir)
    if terraform show -json tf.plan > tfplan.json 2>/dev/null; then
      # Only add if non-empty
      if [ -s tfplan.json ]; then
        plan_jsons+=("$PWD/tfplan.json")
      else
        echo "WARN: empty tfplan.json in $d; skipping."
        rm -f tfplan.json || true
      fi
    else
      echo "WARN: terraform show failed in $d; skipping."
      rm -f tfplan.json || true
    fi
  )
done

if [ "${#plan_jsons[@]}" -eq 0 ]; then
  echo "No tfplan.json files were produced; nothing to scan."
  exit 0
fi

echo "Snyk IaC: scanning ${#plan_jsons[@]} plan JSON(s) with --scan=planned-values ..."
common_args=( "iac" "test" "--severity-threshold=${SNYK_SEVERITY}" "--scan=planned-values" )
[ -n "$SNYK_ORG" ] && common_args+=( "--org=${SNYK_ORG}" )

rc=0
# Chunk to avoid very long argv
chunk_size=50
i=0
total=${#plan_jsons[@]}
while [ $i -lt $total ]; do
  chunk=( "${plan_jsons[@]:$i:$chunk_size}" )
  echo "→ ${#chunk[@]} file(s)"
  # shellcheck disable=SC2086
  if ! snyk "${common_args[@]}" ${SNYK_ADDITIONAL_ARGS} "${chunk[@]}"; then
    rc=1
  fi
  i=$(( i + chunk_size ))
done

exit $rc