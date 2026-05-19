output "kms_secrets_key_arn" {
  description = "ARN of the CMK that wraps observability-tier secrets. Used by Secrets Manager + external-secrets policies."
  value       = module.kms_observability.key_arn
}

output "kms_secrets_alias" {
  description = "Friendly alias for the observability KMS key."
  value       = module.kms_observability.alias
}
