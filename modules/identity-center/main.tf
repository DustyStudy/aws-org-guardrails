locals {
  managed_policy_attachments = merge([
    for ps_name, ps in var.permission_sets : {
      for arn in ps.managed_policy_arns : "${ps_name}/${arn}" => { permission_set = ps_name, arn = arn }
    }
  ]...)

  customer_managed_attachments = merge([
    for ps_name, ps in var.permission_sets : {
      for policy in ps.customer_managed_policies :
      "${ps_name}/${policy.path}${policy.name}" => { permission_set = ps_name, name = policy.name, path = policy.path }
    }
  ]...)

  inline_policies = { for name, ps in var.permission_sets : name => ps.inline_policy if ps.inline_policy != null }
  boundaries      = { for name, ps in var.permission_sets : name => ps.permissions_boundary if ps.permissions_boundary != null }

  missing_boundary = [
    for name, ps in var.permission_sets : name
    if ps.permissions_boundary == null && !contains(var.boundary_exempt_permission_sets, name)
  ]

  assignments = {
    for a in var.account_assignments :
    "${a.permission_set}/${a.principal_type}/${a.principal_id}/${a.account_id}" => a
  }
}

resource "aws_ssoadmin_permission_set" "this" {
  for_each = var.permission_sets

  instance_arn     = var.instance_arn
  name             = each.key
  description      = each.value.description
  session_duration = each.value.session_duration
  relay_state      = each.value.relay_state
  tags             = var.tags

  lifecycle {
    precondition {
      condition     = !var.require_permissions_boundary || length(local.missing_boundary) == 0
      error_message = "These permission sets have no permissions boundary: ${join(", ", local.missing_boundary)}. Add one, or list them in boundary_exempt_permission_sets."
    }
  }
}

resource "aws_ssoadmin_managed_policy_attachment" "this" {
  for_each = local.managed_policy_attachments

  instance_arn       = var.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.value.permission_set].arn
  managed_policy_arn = each.value.arn
}

resource "aws_ssoadmin_customer_managed_policy_attachment" "this" {
  for_each = local.customer_managed_attachments

  instance_arn       = var.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.value.permission_set].arn

  customer_managed_policy_reference {
    name = each.value.name
    path = each.value.path
  }
}

resource "aws_ssoadmin_permission_set_inline_policy" "this" {
  for_each = local.inline_policies

  instance_arn       = var.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.key].arn
  inline_policy      = each.value
}

resource "aws_ssoadmin_permissions_boundary_attachment" "this" {
  for_each = local.boundaries

  instance_arn       = var.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.key].arn

  permissions_boundary {
    managed_policy_arn = each.value.managed_policy_arn

    dynamic "customer_managed_policy_reference" {
      for_each = each.value.customer_managed_policy == null ? [] : [each.value.customer_managed_policy]
      content {
        name = customer_managed_policy_reference.value.name
        path = customer_managed_policy_reference.value.path
      }
    }
  }
}

resource "aws_ssoadmin_account_assignment" "this" {
  for_each = local.assignments

  instance_arn       = var.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.value.permission_set].arn
  principal_type     = each.value.principal_type
  principal_id       = each.value.principal_id
  target_type        = "AWS_ACCOUNT"
  target_id          = each.value.account_id

  # Policies and the boundary must be in place before anyone can sign in
  # with the permission set, or the first session would run without them.
  depends_on = [
    aws_ssoadmin_managed_policy_attachment.this,
    aws_ssoadmin_customer_managed_policy_attachment.this,
    aws_ssoadmin_permission_set_inline_policy.this,
    aws_ssoadmin_permissions_boundary_attachment.this,
  ]
}
