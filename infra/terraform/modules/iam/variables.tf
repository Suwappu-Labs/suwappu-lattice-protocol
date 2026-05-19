variable "name" {
  type        = string
  description = "Env name prefix. Roles become <name>-<service>-irsa."
}

variable "oidc_provider_arn" {
  type        = string
  description = "OIDC provider ARN from the eks module. Roles trust this provider for the matching k8s service account."
}

variable "oidc_provider_url" {
  type        = string
  description = "OIDC issuer URL (hostname only, no protocol). Used in the trust condition."
}

variable "kms_key_arn" {
  type        = string
  description = "KMS CMK that etp-node and etp-gateway need Encrypt/Decrypt on (config wrapping, future signing-key wrapping)."
}

variable "ecr_repository_arns" {
  type        = list(string)
  description = "ECR repo ARNs the service accounts need pull access to."
}

variable "secrets_manager_arn_prefix" {
  type        = string
  description = "Secrets Manager ARN prefix etp pods can read (e.g. \"arn:aws:secretsmanager:us-east-1:<acct>:secret:ltp/*\"). External-secrets gets the matching policy."
}

variable "tags" {
  type        = map(string)
  description = "Extra tags applied to every role."
  default     = {}
}
