# `infra/terraform/` — LTP AWS infrastructure

Terraform that stands up the AWS-side foundation for the LTP production
roll-out described in [`docs/DEPLOYMENT_GUIDE.md`](../../docs/DEPLOYMENT_GUIDE.md).

This PR (B1 in the roll-out plan) ships **scaffolding only** — every
`terraform apply` is gated on an operator with the right AWS credentials
and the governance answers from the plan's *Open governance* table.

## Layout

```
terraform/
├── README.md          ← this file
├── modules/
│   ├── vpc/           ← single-VPC, 2-AZ, private+public subnets, NAT
│   ├── eks/           ← EKS cluster + managed node group + IRSA OIDC
│   ├── kms/           ← root keys (per env) + alias + key policy
│   ├── ecr/           ← etp-node and etp-gateway repos (immutable tags)
│   └── iam/           ← IRSA roles for etp-node, etp-gateway, monitoring
└── envs/
    ├── prod/          ← composes all five modules
    └── observability/ ← split state, smaller stack for Prometheus/Grafana
```

Each env has its own `backend.tf` pointing at an `s3` backend with a
distinct state key. The state bucket + DynamoDB lock table are bootstrap
resources that must exist before `terraform init` — see the bootstrap
section below.

## Bootstrap (one-time, per AWS account)

The state backend has to exist before Terraform can manage anything else.

```bash
# Replace ACCOUNT_ID and REGION first.
export AWS_PROFILE=ltp-prod                 # set in ~/.aws/config
export AWS_REGION=us-east-1
export BUCKET="ltp-tfstate-${AWS_ACCOUNT_ID}-${AWS_REGION}"
export TABLE="ltp-tfstate-lock"

aws s3api create-bucket \
  --bucket "$BUCKET" \
  --region "$AWS_REGION" \
  --create-bucket-configuration LocationConstraint="$AWS_REGION"

aws s3api put-bucket-versioning \
  --bucket "$BUCKET" \
  --versioning-configuration Status=Enabled

aws s3api put-bucket-encryption \
  --bucket "$BUCKET" \
  --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

aws s3api put-public-access-block \
  --bucket "$BUCKET" \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

aws dynamodb create-table \
  --table-name "$TABLE" \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
```

After bootstrap, fill in `envs/<env>/terraform.tfvars` with the
account-specific values (account id, KMS admin principals, signer
addresses where applicable) and run:

```bash
cd envs/prod
terraform init \
  -backend-config="bucket=${BUCKET}" \
  -backend-config="key=prod/terraform.tfstate" \
  -backend-config="region=${AWS_REGION}" \
  -backend-config="dynamodb_table=${TABLE}"
terraform plan -out plan.bin   # review carefully
terraform apply plan.bin       # only after sign-off
```

## Verifying without applying

The plan in this PR has only been `terraform validate`-d locally, not
applied. To prove the modules compose without an AWS account:

```bash
cd envs/prod && terraform init -backend=false && terraform validate
cd ../observability && terraform init -backend=false && terraform validate
```

CI runs the same two commands (see `.github/workflows/terraform.yml` —
landing alongside this PR).

## Provider pins

Provider versions are pinned per LTP-A-025-style hygiene (SHA-pin for
GitHub Actions; version-pin for Terraform). The pins live in each
module's `versions.tf`. To bump, change the pin, run
`terraform init -upgrade`, and review the new `.terraform.lock.hcl`.

## Out of scope for this PR

- `terraform apply` against any real AWS account (deliberate — needs
  governance answers from the plan's *Open governance* table)
- A `terraform-plan` GitHub Action that posts diffs to PRs (follow-up
  once the state bucket exists)
- Helm chart authoring (PR B2, separate)
- Container image building (PR C1, later phase)
