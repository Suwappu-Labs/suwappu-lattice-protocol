variable "name" {
  type        = string
  description = "Name prefix applied to every VPC resource. Typically the env name (e.g. \"ltp-prod\")."
}

variable "cidr" {
  type        = string
  description = "Top-level VPC CIDR (e.g. \"10.20.0.0/16\")."
}

variable "azs" {
  type        = list(string)
  description = "List of AZs in the target region; subnets are striped across these."
  validation {
    condition     = length(var.azs) >= 2
    error_message = "At least two AZs are required for EKS control-plane HA."
  }
}

variable "tags" {
  type        = map(string)
  description = "Extra tags applied to every resource in the module."
  default     = {}
}
