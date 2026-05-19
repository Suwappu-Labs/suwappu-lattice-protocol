output "etp_node_role_arn" {
  description = "ARN of the IRSA role for the etp-node service account (namespace: ltp)."
  value       = aws_iam_role.etp_node.arn
}

output "etp_gateway_role_arn" {
  description = "ARN of the IRSA role for the etp-gateway service account (namespace: ltp)."
  value       = aws_iam_role.etp_gateway.arn
}

output "external_secrets_role_arn" {
  description = "ARN of the IRSA role for the external-secrets controller (namespace: external-secrets)."
  value       = aws_iam_role.external_secrets.arn
}
