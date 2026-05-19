# LTP EKS cluster.
#
# Posture:
#   - Private endpoint by default (set endpoint_public_access = true to
#     allow operator workstation access; recommended only for early dev)
#   - OIDC provider attached so the iam module can mint IRSA roles for
#     etp-node, etp-gateway, external-secrets, and the Prometheus stack
#   - Cluster encryption uses the kms module's key (set via kms_key_arn);
#     all secrets at rest are wrapped with that CMK
#   - Single managed node group with anti-affinity-friendly subnets
#     across all AZs; nodes get the AmazonEKSWorkerNodePolicy + CNI +
#     ECR read-only baseline policies
#
# Cost note: EKS control plane is $73/mo. Two t3.large nodes is ~$120/mo.
# Plan to migrate to Karpenter once workloads stabilize.

locals {
  common_tags = merge(
    {
      "ltp:module" = "eks"
      "ltp:env"    = var.name
    },
    var.tags,
  )
}

variable "kms_key_arn" {
  type        = string
  description = "KMS CMK that wraps EKS secrets at rest. Supplied by the kms module."
}

resource "aws_iam_role" "cluster" {
  name = "${var.name}-eks-cluster"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "eks.amazonaws.com" }
        Action    = "sts:AssumeRole"
      },
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "cluster_policy" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_eks_cluster" "this" {
  name     = var.name
  role_arn = aws_iam_role.cluster.arn
  version  = var.kubernetes_version

  vpc_config {
    subnet_ids              = concat(var.private_subnet_ids, var.public_subnet_ids)
    endpoint_private_access = true
    endpoint_public_access  = var.endpoint_public_access
  }

  encryption_config {
    provider {
      key_arn = var.kms_key_arn
    }
    resources = ["secrets"]
  }

  enabled_cluster_log_types = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler",
  ]

  tags = local.common_tags

  depends_on = [aws_iam_role_policy_attachment.cluster_policy]
}

data "tls_certificate" "cluster_oidc" {
  url = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "cluster" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.cluster_oidc.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.this.identity[0].oidc[0].issuer

  tags = local.common_tags
}

resource "aws_iam_role" "node_group" {
  name = "${var.name}-eks-node"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      },
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "node_baseline" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
  ])

  role       = aws_iam_role.node_group.name
  policy_arn = each.value
}

resource "aws_eks_node_group" "default" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "${var.name}-default"
  node_role_arn   = aws_iam_role.node_group.arn
  subnet_ids      = var.private_subnet_ids

  instance_types = var.node_instance_types

  scaling_config {
    desired_size = var.node_desired_size
    min_size     = var.node_min_size
    max_size     = var.node_max_size
  }

  update_config {
    max_unavailable_percentage = 25
  }

  tags = local.common_tags

  depends_on = [aws_iam_role_policy_attachment.node_baseline]
}
