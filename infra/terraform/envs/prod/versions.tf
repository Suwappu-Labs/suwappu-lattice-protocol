terraform {
  required_version = ">= 1.5.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # Backend is configured at `terraform init` time via -backend-config
  # flags; see infra/terraform/README.md for the bootstrap recipe.
  backend "s3" {
    key          = "prod/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}
