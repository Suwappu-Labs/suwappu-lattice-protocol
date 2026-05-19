output "key_id" {
  description = "Key ID (UUID-ish) of the CMK."
  value       = aws_kms_key.this.key_id
}

output "key_arn" {
  description = "Full ARN of the CMK. Use in eks encryption_config and IAM policies that grant kms:* on a specific key."
  value       = aws_kms_key.this.arn
}

output "alias" {
  description = "Friendly alias for the key (alias/<name>). Use this in app config."
  value       = aws_kms_alias.this.name
}
