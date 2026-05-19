variable "name" {
  type        = string
  description = "Name prefix and alias (alias becomes alias/<name>)."
}

variable "description" {
  type        = string
  description = "Human-readable description of the key's purpose."
}

variable "admin_principal_arns" {
  type        = list(string)
  description = "IAM principals that can administer the key (rotate, schedule deletion, change policy). Should be a break-glass role plus a CI/CD role. If empty, only the account root can administer the key — acceptable for low-trust secret-wrapping keys, not for signing keys."
  default     = []
}

variable "user_principal_arns" {
  type        = list(string)
  description = "IAM principals that can use the key for Encrypt/Decrypt/GenerateDataKey but cannot administer it."
  default     = []
}

variable "enable_key_rotation" {
  type        = bool
  description = "Whether AWS-managed annual key rotation is enabled."
  default     = true
}

variable "deletion_window_in_days" {
  type        = number
  description = "Pending-deletion window (7-30 days). Production should be at the upper end."
  default     = 30
}

variable "tags" {
  type        = map(string)
  description = "Extra tags applied to the key and alias."
  default     = {}
}
