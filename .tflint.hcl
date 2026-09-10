# Each Terraform root here (terraform/, terraform/evidence-vault/,
# terraform/oidc-trust/) is linted on its own via `tflint --chdir` in the
# CI lint job. The "recommended" preset adds documentation/naming/typing
# checks on top of the always-on correctness rules; CI treats only
# error-severity issues as blocking (--minimum-failure-severity=error).
plugin "terraform" {
  enabled = true
  preset  = "recommended"
}
