# Search for all accounts in the organization
data "aws_organizations_organization" "all" {}

locals {
  account_name_to_id = {
    for account in data.aws_organizations_organization.all.accounts : account.name => account.id
  }
}

# Search for all OUs under the root
data "aws_organizations_organizational_units" "root" {
  parent_id = var.organization_root_id
}

locals {
  ou_name_to_id = {
    for ou in data.aws_organizations_organizational_units.root.children : ou.name => ou.id
  }
}
