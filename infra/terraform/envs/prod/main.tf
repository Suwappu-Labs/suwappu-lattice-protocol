# LTP production environment.
#
# Composes all five modules to stand up:
#   - VPC (private + public subnets across 2 AZ, NAT per AZ)
#   - KMS CMK for env-wide secret/config wrapping
#   - EKS cluster (private endpoint, encryption_config wired to the CMK)
#   - ECR repositories for etp-node and etp-gateway images
#   - IRSA roles for the workloads + external-secrets controller
#
# Apply order is implicit through resource dependencies — Terraform
# resolves it. The recommended workflow is plan/apply in one shot from
# an operator workstation with -out=plan.bin per
# infra/terraform/README.md.

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = var.tags
  }
}

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# VPC
# ---------------------------------------------------------------------------

module "vpc" {
  source = "../../modules/vpc"

  name = var.name
  cidr = var.vpc_cidr
  azs  = var.azs

  tags = var.tags
}

# ---------------------------------------------------------------------------
# KMS — one symmetric CMK for the env. The eks module wraps secrets with
# it; the iam module grants Encrypt/Decrypt to etp-node + etp-gateway.
# ---------------------------------------------------------------------------

module "kms_env" {
  source = "../../modules/kms"

  name                 = "${var.name}-env"
  description          = "LTP ${var.name} env CMK — wraps EKS secrets, Secrets Manager envelope keys, and config payloads consumed by etp-node and etp-gateway."
  admin_principal_arns = var.kms_admin_principal_arns
  tags                 = var.tags
}

# ---------------------------------------------------------------------------
# EKS
# ---------------------------------------------------------------------------

module "eks" {
  source = "../../modules/eks"

  name               = var.name
  kubernetes_version = var.kubernetes_version
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  public_subnet_ids  = module.vpc.public_subnet_ids
  kms_key_arn        = module.kms_env.key_arn

  endpoint_public_access = false # Operator access goes through bastion/VPN

  tags = var.tags
}

# ---------------------------------------------------------------------------
# ECR
# ---------------------------------------------------------------------------

module "ecr" {
  source = "../../modules/ecr"

  repositories = ["etp-node", "etp-gateway"]
  tags         = var.tags
}

# ---------------------------------------------------------------------------
# IAM — IRSA roles
# ---------------------------------------------------------------------------

module "iam" {
  source = "../../modules/iam"

  name              = var.name
  oidc_provider_arn = module.eks.oidc_provider_arn
  oidc_provider_url = module.eks.oidc_provider_url
  kms_key_arn       = module.kms_env.key_arn
  ecr_repository_arns = [
    module.ecr.repository_arns["etp-node"],
    module.ecr.repository_arns["etp-gateway"],
  ]
  secrets_manager_arn_prefix = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:ltp/*"

  tags = var.tags
}
