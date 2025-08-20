# pre-commit hooks: Terragrunt + Snyk IaC

Pre-commit hooks to:
- Scan Terraform/Terragrunt changes with Snyk CLI (`snyk iac test`)

## Requirements
- [pre-commit](https://pre-commit.com/) installed
- [Snyk CLI](https://docs.snyk.io/snyk-cli/install-the-snyk-cli) installed & authenticated
  - Either run `snyk auth` once or export `SNYK_TOKEN`
- [Terragrunt](https://terragrunt.gruntwork.io/) for the formatting hook

## Install

Add to your repo’s `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/<your-org>/pre-commit-terragrunt-snyk
    rev: v0.1.0
    hooks:
      - id: snyk-iac
        # Optional args via env:
        #   SNYK_SEVERITY=high SNYK_ORG=my-org SNYK_ADDITIONAL_ARGS="--report"
```