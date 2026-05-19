variable "name" {
  type        = string
  description = "Cluster name. Must match the kubernetes.io/cluster/<name> tag on subnets."
}

variable "kubernetes_version" {
  type        = string
  description = "EKS control-plane version."
  default     = "1.31"
}

variable "vpc_id" {
  type        = string
  description = "VPC the cluster lives in. Supplied by the vpc module's vpc_id output."
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Private subnets for the node group and control-plane ENIs."
}

variable "public_subnet_ids" {
  type        = list(string)
  description = "Public subnets — only used for the public API endpoint when enabled."
  default     = []
}

variable "endpoint_public_access" {
  type        = bool
  description = "Whether the EKS control-plane API is reachable from the public internet."
  default     = false
}

variable "node_instance_types" {
  type        = list(string)
  description = "Instance types for the managed node group."
  default     = ["t3.large"]
}

variable "node_desired_size" {
  type        = number
  description = "Desired node count."
  default     = 2
}

variable "node_min_size" {
  type        = number
  description = "Minimum node count (Cluster Autoscaler floor)."
  default     = 2
}

variable "node_max_size" {
  type        = number
  description = "Maximum node count (Cluster Autoscaler ceiling)."
  default     = 6
}

variable "tags" {
  type        = map(string)
  description = "Extra tags applied to every resource."
  default     = {}
}
