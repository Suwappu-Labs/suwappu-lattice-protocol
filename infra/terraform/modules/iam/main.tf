# IRSA roles for the LTP workloads.
#
# We define one role per Kubernetes service account:
#   - etp-node (in namespace ltp)
#   - etp-gateway (in namespace ltp)
#   - external-secrets-controller (in namespace external-secrets)
#
# Each role's trust policy ties it to a single service account; the
# Helm chart (PR C2) sets `serviceAccountName` and the
# `eks.amazonaws.com/role-arn` annotation that completes the binding.
#
# The policies are deliberately minimal — each role gets only what its
# workload needs (least-privilege per FedRAMP AC-6).

locals {
  oidc_provider_host = replace(var.oidc_provider_url, "https://", "")

  common_tags = merge(
    {
      "ltp:module" = "iam"
      "ltp:env"    = var.name
    },
    var.tags,
  )
}

# ---------------------------------------------------------------------------
# Helper: build an IRSA trust policy for a namespace + service-account pair
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "etp_node_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_provider_host}:sub"
      values   = ["system:serviceaccount:ltp:etp-node"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_provider_host}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "etp_gateway_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_provider_host}:sub"
      values   = ["system:serviceaccount:ltp:etp-gateway"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_provider_host}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "external_secrets_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_provider_host}:sub"
      values   = ["system:serviceaccount:external-secrets:external-secrets"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_provider_host}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

# ---------------------------------------------------------------------------
# Shared per-role permission policies
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "etp_node_perms" {
  statement {
    sid    = "KmsEncryptDecryptOnEnvKey"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = [var.kms_key_arn]
  }

  statement {
    sid    = "EcrPullForNodeImage"
    effect = "Allow"
    actions = [
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "ecr:BatchCheckLayerAvailability",
    ]
    resources = var.ecr_repository_arns
  }

  statement {
    sid       = "EcrGetAuthorizationToken"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "etp_gateway_perms" {
  # Same shape as etp-node for now; diverges if/when the gateway needs
  # narrower Secrets Manager scopes.
  source_policy_documents = [data.aws_iam_policy_document.etp_node_perms.json]
}

data "aws_iam_policy_document" "external_secrets_perms" {
  statement {
    sid    = "ReadLtpSecrets"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
      "secretsmanager:ListSecrets",
    ]
    resources = [var.secrets_manager_arn_prefix]
  }

  statement {
    sid    = "KmsDecryptForSecretsManagerEnvelope"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    resources = [var.kms_key_arn]
  }
}

# ---------------------------------------------------------------------------
# Roles + inline policies
# ---------------------------------------------------------------------------

resource "aws_iam_role" "etp_node" {
  name               = "${var.name}-etp-node-irsa"
  assume_role_policy = data.aws_iam_policy_document.etp_node_trust.json
  tags               = local.common_tags
}

resource "aws_iam_role_policy" "etp_node" {
  name   = "${var.name}-etp-node-perms"
  role   = aws_iam_role.etp_node.id
  policy = data.aws_iam_policy_document.etp_node_perms.json
}

resource "aws_iam_role" "etp_gateway" {
  name               = "${var.name}-etp-gateway-irsa"
  assume_role_policy = data.aws_iam_policy_document.etp_gateway_trust.json
  tags               = local.common_tags
}

resource "aws_iam_role_policy" "etp_gateway" {
  name   = "${var.name}-etp-gateway-perms"
  role   = aws_iam_role.etp_gateway.id
  policy = data.aws_iam_policy_document.etp_gateway_perms.json
}

resource "aws_iam_role" "external_secrets" {
  name               = "${var.name}-external-secrets-irsa"
  assume_role_policy = data.aws_iam_policy_document.external_secrets_trust.json
  tags               = local.common_tags
}

resource "aws_iam_role_policy" "external_secrets" {
  name   = "${var.name}-external-secrets-perms"
  role   = aws_iam_role.external_secrets.id
  policy = data.aws_iam_policy_document.external_secrets_perms.json
}
