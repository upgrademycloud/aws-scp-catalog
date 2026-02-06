variable "aws_region" {
  description = "The AWS region to use"
  default     = "eu-west-1"
}

variable "environment" {
  description = "The environment to deploy to (e.g. production)"
  default     = "organization"
}

variable "state_bucket_name" {
  description = "Name of the S3 bucket for the Terraform statefile"
  default     = "mycompany-organization-terraform-state"
}

variable "organization_root_id" {
  description = "The root ID of the AWS Organization (e.g., r-xxxx). Required when attaching SCPs to root."
  type        = string
  default     = ""
}
