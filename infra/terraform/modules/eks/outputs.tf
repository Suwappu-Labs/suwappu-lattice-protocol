output "cluster_name" {
  description = "Name of the EKS cluster."
  value       = aws_eks_cluster.this.name
}

output "cluster_endpoint" {
  description = "Kubernetes API endpoint URL."
  value       = aws_eks_cluster.this.endpoint
}

output "cluster_certificate_authority" {
  description = "Base64-encoded cluster CA cert. Pipe to kubeconfig clusters[].cluster.certificate-authority-data."
  value       = aws_eks_cluster.this.certificate_authority[0].data
}

output "oidc_provider_arn" {
  description = "OIDC provider ARN for IRSA role trust policies."
  value       = aws_iam_openid_connect_provider.cluster.arn
}

output "oidc_provider_url" {
  description = "Issuer URL of the OIDC provider (used in IRSA trust conditions)."
  value       = aws_iam_openid_connect_provider.cluster.url
}

output "node_role_arn" {
  description = "IAM role ARN attached to the managed node group instances."
  value       = aws_iam_role.node_group.arn
}
