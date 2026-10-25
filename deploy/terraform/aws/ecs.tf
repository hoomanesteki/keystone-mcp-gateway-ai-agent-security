resource "aws_ecr_repository" "keystone" {
  name         = var.name
  force_delete = true

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_cloudwatch_log_group" "keystone" {
  name              = "/ecs/${var.name}"
  retention_in_days = var.log_retention_days
}

resource "aws_ecs_cluster" "main" {
  name = var.name

  setting {
    name  = "containerInsights"
    value = "disabled"
  }
}

locals {
  image    = var.image != "" ? var.image : "${aws_ecr_repository.keystone.repository_url}:latest"
  lb_name  = aws_lb.main.dns_name
  base_url = var.public_base_url != "" ? var.public_base_url : "${local.https ? "https" : "http"}://${local.lb_name}"

  oidc_issuer = var.enable_cognito ? "https://cognito-idp.${var.region}.amazonaws.com/${aws_cognito_user_pool.main[0].id}" : var.oidc_issuer
  # Cognito ID tokens carry the app client id as `aud`; see the README for what that means for the
  # other clients.
  oidc_audience = var.enable_cognito ? aws_cognito_user_pool_client.console[0].id : var.oidc_audience

  allowed_hosts = concat([local.lb_name, "127.0.0.1:*"], var.extra_allowed_hosts)

  environment = merge(
    {
      # Keystone in prod refuses an http public URL, issuer or discovery address. Without a
      # certificate the ALB serves http, so the task runs in dev mode: a trial from your own
      # address, not a deployment (README, "Without a certificate").
      KEYSTONE_ENV = local.https ? "prod" : "dev"
      # In dev the audit log fails open by default. Keep it closed here: dev mode on AWS exists
      # to relax the https rule, not that.
      KEYSTONE_AUDIT__FAIL_CLOSED = "true"
      # Fargate has no Docker socket. The sandbox needs one, so it is off here (README).
      KEYSTONE_SANDBOX_ENABLED    = "false"
      KEYSTONE_AUTH__MODE         = "oidc"
      KEYSTONE_PUBLIC_BASE_URL    = local.base_url
      KEYSTONE_ALLOWED_HOSTS      = jsonencode(local.allowed_hosts)
      KEYSTONE_SCANNER_CLASSIFIER = var.scanner_classifier
      # The upstreams of a deployment sit in the VPC, on private addresses, which the SSRF guard
      # (KS-202) refuses unless told so.
      KEYSTONE_ALLOW_PRIVATE_UPSTREAMS = tostring(var.allow_private_upstreams)
    },
    local.oidc_issuer == "" ? {} : {
      KEYSTONE_OIDC_ISSUER   = local.oidc_issuer
      KEYSTONE_OIDC_AUDIENCE = local.oidc_audience
    },
    var.enable_adot ? { KEYSTONE_OTLP_ENDPOINT = "http://localhost:4318" } : {},
  )

  # Pairs of the variable Keystone reads and the name of its secret in secrets.tf.
  secret_env = [
    ["KEYSTONE_DATABASE_URL", "database-url"],
    ["KEYSTONE_MIGRATE_DATABASE_URL", "migrate-database-url"],
    ["KEYSTONE_APP_DB_PASSWORD", "app-db-password"],
    ["KEYSTONE_MASTER_KEYS", "master-keys"],
    ["KEYSTONE_REDIS_URL", "redis-url"],
  ]

  keystone_container = {
    name      = "keystone"
    image     = local.image
    essential = true
    command   = ["serve", "--host", "0.0.0.0", "--port", "8080", "--migrate"]

    portMappings = [{ containerPort = 8080, protocol = "tcp" }]

    environment = [for k, v in local.environment : { name = k, value = v }]
    secrets = concat(
      [
        for pair in local.secret_env : {
          name      = pair[0]
          valueFrom = aws_secretsmanager_secret.keystone[pair[1]].arn
        }
      ],
      # The YAML Keystone starts from, when keystone_config_yaml holds one (secrets.tf). The task
      # has no file to mount, so Keystone reads the text from this variable.
      [
        for parameter in aws_ssm_parameter.config_yaml : {
          name      = "KEYSTONE_CONFIG_YAML"
          valueFrom = parameter.arn
        }
      ],
    )

    readonlyRootFilesystem = false
    healthCheck = {
      command     = ["CMD", "python", "-c", "import urllib.request as u; u.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 60
    }

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.keystone.name
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "keystone"
      }
    }
  }

  adot_container = {
    name      = "adot"
    image     = var.adot_image
    essential = false
    command   = ["--config=/etc/ecs/ecs-xray.yaml"]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.keystone.name
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "adot"
      }
    }
  }
}

resource "aws_ecs_task_definition" "keystone" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode(
    concat([local.keystone_container], [for c in [local.adot_container] : c if var.enable_adot])
  )

  lifecycle {
    # Keystone would refuse these at startup, and the service would crash-loop behind a load
    # balancer that looks healthy while the NAT gateway and the database bill by the hour.
    precondition {
      condition     = !local.https || var.public_base_url == "" || startswith(var.public_base_url, "https://")
      error_message = "With a certificate the task runs with KEYSTONE_ENV=prod, and Keystone refuses an http public_base_url there. Give an https URL or leave it empty."
    }
    precondition {
      condition     = !local.https || var.enable_cognito || var.oidc_issuer == "" || startswith(var.oidc_issuer, "https://")
      error_message = "With a certificate the task runs with KEYSTONE_ENV=prod, and Keystone refuses an http oidc_issuer there."
    }
  }
}

resource "aws_ecs_service" "keystone" {
  name            = var.name
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.keystone.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  health_check_grace_period_seconds = 120

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.task.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.keystone.arn
    container_name   = "keystone"
    container_port   = 8080
  }

  depends_on = [aws_lb_listener.http, aws_lb_listener.https]
}
