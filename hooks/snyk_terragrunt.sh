#!/usr/bin/env bash
set -euo pipefail

# Workflow:
#   - discover all dirs containing env.hcl
#   - terragrunt plan -> <dir>/.terragrunt-snyk/plan.bin
#   - terraform show -json plan.bin -> <dir>/.terragrunt-snyk/tfplan.json
#   - snyk iac test --scan=planned-values tfplan.json

: "${SNYK_SEVERITY:=medium}"            # low|medium|high|critical
: "${SNYK_ORG:=}"                       # optional
: "${SNYK_ADDITIONAL_ARGS:=}"           # e.g. "--report --sarif-file-output=iac.sarif"
: "${TG_PLAN_ARGS:=-lock=false -input=false -no-color}"
: "${TG_PARALLELISM:=1}"                # set >1 if you want concurrent plans (hook runs serially by default)

need() { command -v "$1" >/dev/null 2>&1 || { echo "$1 not found"; exit 1; }; }
need terragrunt
need terraform
need snyk

# Snyk auth
if ! snyk config get api >/dev/null 2>&1; then
  if [ -n "${SNYK_TOKEN:-}" ]; then
    snyk auth "${SNYK_TOKEN}" >/dev/null
  else
    echo "Snyk CLI not authenticated. Run 'snyk auth' or set SNYK_TOKEN." >&2
    exit 1
  fi
fi

# Find all env.hcl directories
env_dirs=()
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
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

# (Optional) keep Snyk IaC rules updated (fast no-op if current)
if [ "${SNYK_UPDATE_RULES:-1}" = "1" ]; then
  snyk iac rules update >/dev/null || true
fi

# Plan each env dir -> JSON
plan_jsons=()
for d in "${env_dirs[@]}"; do
  outdir="$d/.terragrunt-snyk"
  mkdir -p "$outdir"
  planbin="$outdir/plan.bin"
  planjson="$outdir/tfplan.json"

  echo "Planning: $d"
  (
    cd "$d"
    # Best effort: don’t fail the entire hook if one stack fails
    if terragrunt plan ${TG_PLAN_ARGS} -out="$planbin" >/dev/null 2>&1; then
      if terraform show -json "$planbin" > "$planjson" 2>/dev/null; then
        plan_jsons+=("$planjson")
      else
        echo "WARN: terraform show failed in $d; skipping." >&2
        rm -f "$planjson" || true
      fi
    else
      echo "WARN: terragrunt plan failed in $d; skipping." >&2
      rm -f "$planbin" || true
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
# Chunk to avoid very long command lines
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