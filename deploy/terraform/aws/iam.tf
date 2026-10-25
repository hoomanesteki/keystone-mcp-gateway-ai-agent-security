data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

# The execution role is what ECS itself uses: pull the image, write the log stream, read the
# secrets it injects into the container's environment. Nothing else.
resource "aws_iam_role" "execution" {
  name_prefix        = "${var.name}-exec-"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

data "aws_iam_policy_document" "execution" {
  statement {
    sid       = "PullImage"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid = "PullFromThisRepository"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
    ]
    resources = [aws_ecr_repository.keystone.arn]
  }

  statement {
    sid       = "WriteLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.keystone.arn}:*"]
  }

  statement {
    sid       = "ReadInjectedSecrets"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [for s in aws_secretsmanager_secret.keystone : s.arn]
  }

  # The config YAML, when there is one (secrets.tf). The parameter uses the account's SSM key,
  # which needs no kms:Decrypt of its own.
  dynamic "statement" {
    for_each = aws_ssm_parameter.config_yaml
    content {
      sid       = "ReadConfigParameter"
      actions   = ["ssm:GetParameters"]
      resources = [statement.value.arn]
    }
  }
}

resource "aws_iam_role_policy" "execution" {
  name   = "execution"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution.json
}

# The task role is what Keystone's own code runs as. It needs no AWS API at all, so it holds
# nothing, except the X-Ray write permission when the collector sidecar is on.
resource "aws_iam_role" "task" {
  name_prefix        = "${var.name}-task-"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

data "aws_iam_policy_document" "task_xray" {
  statement {
    sid = "SendTraces"
    actions = [
      "xray:PutTraceSegments",
      "xray:PutTelemetryRecords",
      "xray:GetSamplingRules",
      "xray:GetSamplingTargets",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "task_xray" {
  count  = var.enable_adot ? 1 : 0
  name   = "xray"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task_xray.json
}
