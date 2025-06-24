variable "environment" {
  type        = string
  description = "Environment name (e.g., dev, prod)"
}

variable "vpc_id" {
  type        = string
  description = "VPC ID"
}

variable "public_subnet_ids" {
  type        = list(string)
  description = "List of public subnet IDs"
}

variable "app_security_group_id" {
  type        = string
  description = "Security group ID for the app"
}

variable "ecr_repository_url" {
  type        = string
  description = "ECR repository URL"
}

variable "aws_region" {
  type        = string
  description = "AWS region"
}