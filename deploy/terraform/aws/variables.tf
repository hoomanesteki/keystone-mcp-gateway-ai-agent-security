variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "name" {
  description = "Prefix of every resource name."
  type        = string
  default     = "keystone"
}

variable "image" {
  description = "Keystone container image to run. Empty means the ECR repository this stack creates, tag `latest`."
  type        = string
  default     = ""
}

variable "vpc_cidr" {
  description = "CIDR block of the VPC. Two public and two private /20 subnets are cut from it."
  type        = string
  default     = "10.40.0.0/16"
}

variable "acm_certificate_arn" {
  description = "ACM certificate for the load balancer. When set, the ALB serves HTTPS on 443 and redirects 80 to it. When empty, it serves plain HTTP on 80 (a demo only)."
  type        = string
  default     = ""
}

variable "ingress_cidrs" {
  description = "Who may reach the load balancer. Narrow this to your own address for a demo."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "public_base_url" {
  description = "The address clients use to reach Keystone, for the sign-in metadata. Empty means the load balancer's own name."
  type        = string
  default     = ""
}

variable "extra_allowed_hosts" {
  description = "Host names, beyond the load balancer's, that /mcp accepts in the Host header (for example your DNS alias)."
  type        = list(string)
  default     = []
}

variable "task_cpu" {
  description = "Fargate CPU units for the Keystone task."
  type        = number
  default     = 1024
}

variable "task_memory" {
  description = "Fargate memory in MiB for the Keystone task."
  type        = number
  default     = 2048
}

variable "desired_count" {
  description = "Number of Keystone tasks."
  type        = number
  default     = 1
}

variable "scanner_classifier" {
  description = "Scanner model. `none` runs the rules alone, which the default image (built without the model) needs."
  type        = string
  default     = "none"
}

variable "keystone_config_yaml" {
  description = "Optional contents of keystone.yaml (tenants, upstreams, budgets). Empty means Keystone starts with no upstreams."
  type        = string
  default     = ""
}

variable "db_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.micro"
}

variable "db_allocated_storage_gb" {
  description = "RDS storage in GB."
  type        = number
  default     = 20
}

variable "redis_node_type" {
  description = "ElastiCache node type."
  type        = string
  default     = "cache.t4g.micro"
}

variable "log_retention_days" {
  description = "CloudWatch log retention."
  type        = number
  default     = 7
}

variable "enable_cognito" {
  description = "Create a Cognito user pool with app clients that mirror the Keycloak clients, and point Keystone at it. When false, supply oidc_issuer yourself."
  type        = bool
  default     = false
}

variable "console_callback_urls" {
  description = "Redirect URLs of the console client in Cognito."
  type        = list(string)
  default     = ["http://localhost:5173/"]
}

variable "oidc_issuer" {
  description = "Issuer of an existing identity provider. Used when enable_cognito is false. Empty with Cognito off leaves Keystone with no token validation configured, so it refuses to start in prod."
  type        = string
  default     = ""
}

variable "oidc_audience" {
  description = "Audience Keystone requires in tokens when enable_cognito is false."
  type        = string
  default     = "keystone"
}

variable "enable_adot" {
  description = "Run an AWS Distro for OpenTelemetry collector next to Keystone and send traces to X-Ray."
  type        = bool
  default     = false
}

variable "adot_image" {
  description = "ADOT collector image."
  type        = string
  default     = "public.ecr.aws/aws-observability/aws-otel-collector:v0.43.3"
}

variable "deletion_protection" {
  description = "Protect the database and the load balancer from deletion. Leave false for a demo you will destroy."
  type        = bool
  default     = false
}
