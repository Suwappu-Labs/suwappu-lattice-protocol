output "vpc_id" {
  description = "ID of the VPC."
  value       = aws_vpc.this.id
}

output "vpc_cidr" {
  description = "CIDR block of the VPC."
  value       = aws_vpc.this.cidr_block
}

output "private_subnet_ids" {
  description = "List of private subnet IDs (one per AZ). EKS node groups and StatefulSets land here."
  value       = aws_subnet.private[*].id
}

output "public_subnet_ids" {
  description = "List of public subnet IDs (one per AZ). Internet-facing ALBs land here."
  value       = aws_subnet.public[*].id
}
