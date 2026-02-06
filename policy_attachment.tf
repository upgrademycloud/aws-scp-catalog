# Flatten the OU and account name attachments into a map for for_each
locals {
  ou_attachments = merge([
    for policy_name, policy_config in local.policies : {
      for ou_name in policy_config.ou_names :
      "${policy_name}-${ou_name}" => {
        policy_name = policy_name
        ou_name     = ou_name
      }
    } if !policy_config.attach_to_root && length(policy_config.ou_names) > 0
  ]...)

  account_attachments = merge([
    for policy_name, policy_config in local.policies : {
      for account_name in policy_config.account_names :
      "${policy_name}-${account_name}" => {
        policy_name  = policy_name
        account_name = account_name
      }
    } if !policy_config.attach_to_root && length(policy_config.account_names) > 0
  ]...)

  root_attachments = {
    for policy_name, policy_config in local.policies :
    policy_name => policy_config if policy_config.attach_to_root
  }
}

resource "aws_organizations_policy_attachment" "ou" {
  for_each = local.ou_attachments

  policy_id = aws_organizations_policy.this[each.value.policy_name].id
  target_id = local.ou_name_to_id[each.value.ou_name]
}

resource "aws_organizations_policy_attachment" "account" {
  for_each = local.account_attachments

  policy_id = aws_organizations_policy.this[each.value.policy_name].id
  target_id = local.account_name_to_id[each.value.account_name]
}

resource "aws_organizations_policy_attachment" "root" {
  for_each = local.root_attachments

  policy_id = aws_organizations_policy.this[each.key].id
  target_id = var.organization_root_id
}
