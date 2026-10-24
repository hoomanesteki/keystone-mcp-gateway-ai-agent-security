# A user pool with app clients that mirror the four in deploy/keycloak/realm-keystone.json: three
# confidential clients that sign in with a user name and password, and the console, a public client
# that uses the authorization code flow. Cognito cannot add the `tenant` and `roles` claims that
# Keycloak's mappers add without a pre-token-generation Lambda, which this stack does not include.

resource "aws_cognito_user_pool" "main" {
  count = var.enable_cognito ? 1 : 0

  name                     = var.name
  deletion_protection      = var.deletion_protection ? "ACTIVE" : "INACTIVE"
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]
  mfa_configuration        = "OFF"

  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  password_policy {
    minimum_length    = 12
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = false
  }

  schema {
    name                = "tenant"
    attribute_data_type = "String"
    mutable             = true
    required            = false

    string_attribute_constraints {
      min_length = 1
      max_length = 64
    }
  }
}

resource "aws_cognito_user_pool_domain" "main" {
  count = var.enable_cognito ? 1 : 0

  domain       = "${var.name}-${data.aws_caller_identity.current.account_id}"
  user_pool_id = aws_cognito_user_pool.main[0].id
}

resource "aws_cognito_user_group" "main" {
  for_each = var.enable_cognito ? toset(["admins", "approvers", "operators", "support"]) : toset([])

  name         = each.key
  user_pool_id = aws_cognito_user_pool.main[0].id
}

resource "aws_cognito_user_pool_client" "confidential" {
  for_each = var.enable_cognito ? toset(["support-agent", "ops-agent", "keystone-cli"]) : toset([])

  name         = each.key
  user_pool_id = aws_cognito_user_pool.main[0].id

  generate_secret = true
  explicit_auth_flows = [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
  ]
  prevent_user_existence_errors = "ENABLED"
}

resource "aws_cognito_user_pool_client" "console" {
  count = var.enable_cognito ? 1 : 0

  name         = "console"
  user_pool_id = aws_cognito_user_pool.main[0].id

  generate_secret                      = false
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  supported_identity_providers         = ["COGNITO"]
  callback_urls                        = var.console_callback_urls
  logout_urls                          = var.console_callback_urls
  explicit_auth_flows                  = ["ALLOW_REFRESH_TOKEN_AUTH"]
  prevent_user_existence_errors        = "ENABLED"
}
