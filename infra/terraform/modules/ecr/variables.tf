variable "repositories" {
  type        = set(string)
  description = "ECR repository names to create. Typically [\"etp-node\", \"etp-gateway\"]."
}

variable "image_tag_mutability" {
  type        = string
  description = "IMMUTABLE forbids overwriting existing tags. Required for SLSA build provenance to mean anything."
  default     = "IMMUTABLE"
  validation {
    condition     = contains(["MUTABLE", "IMMUTABLE"], var.image_tag_mutability)
    error_message = "image_tag_mutability must be MUTABLE or IMMUTABLE."
  }
}

variable "scan_on_push" {
  type        = bool
  description = "Enable native ECR vulnerability scanning at push."
  default     = true
}

variable "untagged_image_retention_days" {
  type        = number
  description = "Lifecycle policy: untagged images expire after this many days. Tagged images are kept forever."
  default     = 14
}

variable "tags" {
  type        = map(string)
  description = "Extra tags applied to each repository."
  default     = {}
}
