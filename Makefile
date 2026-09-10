.PHONY: deploy plan test destroy fmt lint validate creds

TF_ROOTS = terraform terraform/evidence-vault terraform/oidc-trust

# Set AWS_PROFILE in your shell before running, or pass on the command line:
#   make deploy AWS_PROFILE=my-sandbox
AWS_PROFILE ?= default

# terraform/backend.tf uses a remote S3 backend (see terraform/oidc-trust/)
# rather than local state, so init needs -backend-config. Override if your
# state bucket has a different name (terraform/oidc-trust output: state_bucket_name).
TF_STATE_BUCKET ?= acme-health-intake-tfstate-4e8f9036
BACKEND_CONFIG = -backend-config="bucket=$(TF_STATE_BUCKET)" -backend-config="key=layer1/terraform.tfstate" -backend-config="region=us-east-1" -backend-config="use_lockfile=true"

# If your profile is AWS SSO-based, the Terraform provider can't always
# read the profile directly. Export credentials into env vars first.
CREDS = eval "$$(aws configure export-credentials --profile $(AWS_PROFILE) --format env)"

deploy: ## Deploy the starter (terraform init + apply)
	@$(CREDS) && cd terraform && terraform init -input=false $(BACKEND_CONFIG) && terraform apply -auto-approve

plan: ## Show what deploy would do
	@$(CREDS) && cd terraform && terraform init -input=false $(BACKEND_CONFIG) && terraform plan

test: ## Smoke test the deployed API
	@$(CREDS) && cd terraform && API_URL=$$(terraform output -raw api_url) && \
		echo "POST $$API_URL" && \
		curl -sS -X POST "$$API_URL" \
			-H 'content-type: application/json' \
			-d '{"patient_id":"P-0001","fields":{"reason":"smoke-test"}}' \
		| python3 -m json.tool

destroy: ## Tear it all down
	@$(CREDS) && cd terraform && terraform init -input=false $(BACKEND_CONFIG) && terraform destroy -auto-approve

fmt: ## Rewrite all .tf/.tftest.hcl to canonical format
	terraform fmt -recursive

lint: ## CI 'lint' stage: fmt check + tflint (all roots) + Rego unit tests
	terraform fmt -check -recursive -diff
	tflint --init
	@for d in $(TF_ROOTS); do \
		echo "tflint $$d" && \
		tflint --chdir="$$d" --config="$$(pwd)/.tflint.hcl" --minimum-failure-severity=error || exit 1; \
	done
	opa test -v policies/

validate: ## CI 'validate' stage: terraform validate per root (no AWS creds)
	@for d in $(TF_ROOTS); do \
		echo "validate $$d" && \
		terraform -chdir="$$d" init -backend=false -input=false >/dev/null && \
		terraform -chdir="$$d" validate || exit 1; \
	done

creds: ## Print the active AWS identity (sanity check)
	@$(CREDS) && aws sts get-caller-identity
