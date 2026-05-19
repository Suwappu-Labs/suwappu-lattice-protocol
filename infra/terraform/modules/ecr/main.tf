# ECR repositories for LTP container images.
#
# Immutable tags are mandatory for SLSA build provenance (PR C1 will
# attach Sigstore attestations keyed by digest; mutable tags would let an
# attacker reuse a verified-attestation tag for a malicious image).
#
# The lifecycle policy is intentionally conservative: only untagged
# images are evicted, and tagged images are kept indefinitely so old
# releases stay reproducible from the same digest CI signed.

locals {
  common_tags = merge(
    {
      "ltp:module" = "ecr"
    },
    var.tags,
  )

  lifecycle_policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images after ${var.untagged_image_retention_days} days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = var.untagged_image_retention_days
        }
        action = { type = "expire" }
      },
    ]
  })
}

resource "aws_ecr_repository" "this" {
  for_each = var.repositories

  name                 = each.value
  image_tag_mutability = var.image_tag_mutability

  image_scanning_configuration {
    scan_on_push = var.scan_on_push
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = merge(local.common_tags, {
    Name = each.value
  })
}

resource "aws_ecr_lifecycle_policy" "this" {
  for_each = aws_ecr_repository.this

  repository = each.value.name
  policy     = local.lifecycle_policy
}
