terraform {
  backend "s3" {
    use_lockfile = true
    bucket       = var.state_bucket_name
    key          = "${var.environment}/scp-catalog/terraform.tfstate"
    region       = var.aws_region
  }
}
