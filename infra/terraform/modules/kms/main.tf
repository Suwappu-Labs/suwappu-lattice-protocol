# Symmetric KMS CMK for LTP secret wrapping.
#
# Used by:
#   - EKS secrets-at-rest encryption (via the eks module's encryption_config)
#   - external-secrets pulling LTP runtime config from AWS Secrets Manager
#   - Future: signing-key wrapping when the etp-node moves off pqcrypto
#     to AWS KMS-backed ML-DSA-65 (FedRAMP-eligible path documented in
#     docs/DEPLOYMENT_GUIDE.md §5).
#
# Key policy is deliberately split into admin vs user statements so that
# the same module can serve a high-trust signing key (admin-only) and a
# lower-trust config-wrapping key (user_principal_arns broader) by
# changing variables, not module code.

data "aws_caller_identity" "current" {}

locals {
  account_root = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
}

resource "aws_kms_key" "this" {
  description             = var.description
  enable_key_rotation     = var.enable_key_rotation
  deletion_window_in_days = var.deletion_window_in_days

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid       = "EnableRootAccountPermissions"
          Effect    = "Allow"
          Principal = { AWS = local.account_root }
          Action    = "kms:*"
          Resource  = "*"
        },
      ],
      length(var.admin_principal_arns) > 0 ? [
        {
          Sid       = "KeyAdministrators"
          Effect    = "Allow"
          Principal = { AWS = var.admin_principal_arns }
          Action = [
            "kms:Create*",
            "kms:Describe*",
            "kms:Enable*",
            "kms:List*",
            "kms:Put*",
            "kms:Update*",
            "kms:Revoke*",
            "kms:Disable*",
            "kms:Get*",
            "kms:Delete*",
            "kms:TagResource",
            "kms:UntagResource",
            "kms:ScheduleKeyDeletion",
            "kms:CancelKeyDeletion",
          ]
          Resource = "*"
        },
      ] : [],
      length(var.user_principal_arns) > 0 ? [
        {
          Sid       = "KeyUsers"
          Effect    = "Allow"
          Principal = { AWS = var.user_principal_arns }
          Action = [
            "kms:Encrypt",
            "kms:Decrypt",
            "kms:ReEncrypt*",
            "kms:GenerateDataKey*",
            "kms:DescribeKey",
          ]
          Resource = "*"
        },
      ] : [],
    )
  })

  tags = merge(
    {
      "ltp:module" = "kms"
      "ltp:env"    = var.name
    },
    var.tags,
  )
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.name}"
  target_key_id = aws_kms_key.this.key_id
}
