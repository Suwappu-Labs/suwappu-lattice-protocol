output "vpc_id" {
  description = "VPC ID — useful when wiring additional infra (e.g. a bastion module)."
  value       = module.vpc.vpc_id
}

output "cluster_name" {
  description = "EKS cluster name for `aws eks update-kubeconfig`."
  value       = module.eks.cluster_name
}

output "cluster_endpoint" {
  description = "Kubernetes API endpoint."
  value       = module.eks.cluster_endpoint
  sensitive   = true
}

output "kms_env_key_arn" {
  description = "Env KMS CMK ARN — supply to Helm values that need explicit KMS context."
  value       = module.kms_env.key_arn
}

output "ecr_repository_urls" {
  description = "Repo name → pull URL for the Helm chart's image.repository field."
  value       = module.ecr.repository_urls
}

output "etp_node_role_arn" {
  description = "IRSA role for etp-node — paste into Helm value `serviceAccount.annotations[\"eks.amazonaws.com/role-arn\"]`."
  value       = module.iam.etp_node_role_arn
}

output "etp_gateway_role_arn" {
  description = "IRSA role for etp-gateway."
  value       = module.iam.etp_gateway_role_arn
}

output "external_secrets_role_arn" {
  description = "IRSA role for the external-secrets controller (namespace external-secrets)."
  value       = module.iam.external_secrets_role_arn
}
