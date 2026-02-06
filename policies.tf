resource "aws_organizations_policy" "this" {
  depends_on = [aws_organizations_organization.this]
  for_each   = local.policies

  name        = each.key
  description = each.value.description
  type        = "SERVICE_CONTROL_POLICY"
  content     = each.value.content
}
