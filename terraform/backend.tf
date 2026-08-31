# terraform/backend.tf
#
# Bucket/key/region are supplied via -backend-config at init time
# (locally and in CI), not hardcoded here -- backend blocks can't
# reference variables. See terraform/oidc-trust for the bucket itself.
terraform {
  backend "s3" {
    key          = "layer1/terraform.tfstate"
    region       = "us-east-1"
    use_lockfile = true
  }
}
