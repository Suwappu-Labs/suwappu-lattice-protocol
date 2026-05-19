variable "aws_region" {
  type        = string
  description = "AWS region this env lives in. Default mirrors the suwappubot account convention."
  default     = "us-east-1"
}

variable "name" {
  type        = string
  description = "Env name prefix. Becomes the EKS cluster name and the prefix on every resource tag."
  default     = "ltp-prod"
}

variable "vpc_cidr" {
  type        = string
  description = "Top-level VPC CIDR."
  default     = "10.20.0.0/16"
}

variable "azs" {
  type        = list(string)
  description = "Availability zones to stripe subnets across."
  default     = ["us-east-1a", "us-east-1b"]
}

variable "kubernetes_version" {
  type        = string
  description = "EKS control-plane version."
  default     = "1.31"
}

variable "kms_admin_principal_arns" {
  type        = list(string)
  description = "IAM principal ARNs that can administer (rotate, delete) the env KMS key. MUST include a break-glass role; otherwise the key is unmanageable if the user list goes stale."
  default     = []
}

variable "tags" {
  type        = map(string)
  description = "Extra tags applied to every resource."
  default = {
    "ltp:owner"       = "platform"
    "ltp:cost-center" = "ltp-prod"
    "ltp:repo"        = "gsx-lattice-protocol"
  }
}
