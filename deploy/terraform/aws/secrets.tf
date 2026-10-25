# Every value below is generated here and read by the task from Secrets Manager. None is written in
# a .tf file or a tfvars file. They do sit in the Terraform state, so keep the state private
# (an encrypted S3 backend for anything beyond a demo).

resource "random_password" "db_admin" {
  length  = 32
  special = false
}

resource "random_password" "db_app" {
  length  = 32
  special = false
}

resource "random_bytes" "master_key" {
  length = 32
}

locals {
  # A Fernet key is 32 random bytes in URL-safe base64.
  master_key = replace(replace(random_bytes.master_key.base64, "+", "-"), "/", "_")

  db_host = aws_db_instance.main.address

  secret_values = {
    database-url         = "postgresql+asyncpg://keystone_app:${random_password.db_app.result}@${local.db_host}:5432/keystone"
    migrate-database-url = "postgresql+asyncpg://keystone:${random_password.db_admin.result}@${local.db_host}:5432/keystone"
    app-db-password      = random_password.db_app.result
    master-keys          = local.master_key
    redis-url            = "rediss://${aws_elasticache_replication_group.main.primary_endpoint_address}:6379/0"
  }
}

resource "aws_secretsmanager_secret" "keystone" {
  for_each = local.secret_values

  name_prefix             = "${var.name}/${each.key}-"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "keystone" {
  for_each = local.secret_values

  secret_id     = aws_secretsmanager_secret.keystone[each.key].id
  secret_string = each.value
}

# The YAML Keystone starts from, when the variable holds one. ECS reads a parameter into the
# container's environment the way it reads a secret, and Keystone takes the text from
# KEYSTONE_CONFIG_YAML (docs/runbook.md, Keystone settings). The standard tier holds 4 KB, which
# fits a few upstreams; a longer file takes the advanced tier (8 KB, $0.05 a month).
resource "aws_ssm_parameter" "config_yaml" {
  count = var.keystone_config_yaml != "" ? 1 : 0

  name  = "/${var.name}/config-yaml"
  type  = "SecureString"
  tier  = length(var.keystone_config_yaml) > 4096 ? "Advanced" : "Standard"
  value = var.keystone_config_yaml
}
