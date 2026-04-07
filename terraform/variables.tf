variable "aws_region" {
  description = "The AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "ssh_key_name" {
  description = "Your pre-existing AWS SSH Keypair Name"
  type        = string
}

variable "admin_ip" {
  description = "Your local public IP address (for SSH whitelisting), e.g., '198.51.100.1/32'"
  type        = string
  default     = "0.0.0.0/0"
}
