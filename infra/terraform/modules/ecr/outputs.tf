output "repository_urls" {
  description = "Map of repository name -> ECR pull URL. Use in Helm values for image.repository."
  value       = { for k, v in aws_ecr_repository.this : k => v.repository_url }
}

output "repository_arns" {
  description = "Map of repository name -> ARN. Use in IAM policies that grant ECR pull rights to IRSA roles."
  value       = { for k, v in aws_ecr_repository.this : k => v.arn }
}
