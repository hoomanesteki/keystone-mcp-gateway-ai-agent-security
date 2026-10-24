output "keystone_url" {
  description = "Where Keystone answers."
  value       = local.base_url
}

output "alb_dns_name" {
  description = "DNS name of the load balancer. Point your own record at it when you use a certificate."
  value       = aws_lb.main.dns_name
}

output "ecr_repository_url" {
  description = "Push the Keystone image here (see the README)."
  value       = aws_ecr_repository.keystone.repository_url
}

output "log_group" {
  description = "CloudWatch log group of the task."
  value       = aws_cloudwatch_log_group.keystone.name
}

output "oidc_issuer" {
  description = "Issuer Keystone validates tokens against."
  value       = local.oidc_issuer
}

output "cognito_client_ids" {
  description = "Cognito app client ids by name (empty when enable_cognito is false). Secrets are read from the console or the API, not from state outputs."
  value = var.enable_cognito ? merge(
    { for name, c in aws_cognito_user_pool_client.confidential : name => c.id },
    { console = aws_cognito_user_pool_client.console[0].id },
  ) : {}
}
