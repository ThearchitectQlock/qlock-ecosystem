# ═══════════════════════════════════════════════════════════════════════
# GodShield API on AWS — ECS Fargate behind an Application Load Balancer
#
#   terraform init
#   terraform apply -var 'vpc_id=vpc-…' \
#     -var 'public_subnet_ids=["subnet-a","subnet-b"]' \
#     -var 'private_subnet_ids=["subnet-c","subnet-d"]' \
#     -var 'image_tag=<git sha>' -var 'certificate_arn=arn:aws:acm:…'
#
# Changes from the version in the deployment-scripts document:
#   - The load balancer had no listener, so nothing could reach it.
#     HTTPS listener on 443 (with an HTTP→HTTPS redirect) added.
#   - The ALB sat in private subnets with internal = false. A public ALB
#     needs public subnets; the tasks stay private.
#   - Tasks accepted traffic from 0.0.0.0/0 directly. They now accept
#     only the load balancer's security group.
#   - Images were pulled as :latest from an IMMUTABLE repository — the
#     second push of `latest` fails. Tagged by git SHA via image_tag.
#   - The awslogs log group was referenced but never created.
#   - Container port 8090, matching docker/Dockerfile.godshield.
# ═══════════════════════════════════════════════════════════════════════

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = var.aws_region
}

# ── Variables ───────────────────────────────────────────────────────────

variable "aws_region" {
  type    = string
  default = "us-east-1"
}
variable "app_name" {
  type    = string
  default = "godshield-api"
}
variable "container_port" {
  type    = number
  default = 8090
}
variable "vpc_id" { type = string }
variable "public_subnet_ids" { type = list(string) }
variable "private_subnet_ids" { type = list(string) }
variable "image_tag" {
  type        = string
  description = "Git SHA of the image to run. Never 'latest'."
}
variable "certificate_arn" {
  type        = string
  description = "ACM certificate for the HTTPS listener."
}
variable "allowed_origin" {
  type    = string
  default = "https://q-lock-ecosystem.com"
}
variable "admin_token_secret_arn" {
  type        = string
  default     = ""
  description = "Optional Secrets Manager ARN holding GODSHIELD_ADMIN_TOKEN."
}

# ── Registry, logs, cluster ─────────────────────────────────────────────

resource "aws_ecr_repository" "godshield" {
  name                 = var.app_name
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
}

resource "aws_cloudwatch_log_group" "godshield" {
  name              = "/ecs/${var.app_name}"
  retention_in_days = 30
}

resource "aws_ecs_cluster" "godshield" {
  name = "${var.app_name}-cluster"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# ── IAM ─────────────────────────────────────────────────────────────────

resource "aws_iam_role" "ecs_execution" {
  name = "${var.app_name}-ecs-execution"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "read_admin_token" {
  count = var.admin_token_secret_arn == "" ? 0 : 1
  name  = "${var.app_name}-read-admin-token"
  role  = aws_iam_role.ecs_execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [var.admin_token_secret_arn]
    }]
  })
}

# ── Task and service ────────────────────────────────────────────────────

resource "aws_ecs_task_definition" "godshield" {
  family                   = var.app_name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.ecs_execution.arn

  container_definitions = jsonencode([{
    name         = var.app_name
    image        = "${aws_ecr_repository.godshield.repository_url}:${var.image_tag}"
    portMappings = [{ containerPort = var.container_port, protocol = "tcp" }]
    environment = [
      { name = "RUST_LOG", value = "info" },
      { name = "GODSHIELD_PORT", value = tostring(var.container_port) },
      { name = "GODSHIELD_ALLOWED_ORIGIN", value = var.allowed_origin },
    ]
    secrets = var.admin_token_secret_arn == "" ? [] : [
      { name = "GODSHIELD_ADMIN_TOKEN", valueFrom = var.admin_token_secret_arn }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.godshield.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "ecs"
      }
    }
    healthCheck = {
      command  = ["CMD-SHELL", "curl -fsS http://localhost:${var.container_port}/health || exit 1"]
      interval = 30
      timeout  = 5
      retries  = 3
    }
  }])
}

resource "aws_ecs_service" "godshield" {
  name            = var.app_name
  cluster         = aws_ecs_cluster.godshield.id
  task_definition = aws_ecs_task_definition.godshield.arn
  desired_count   = 3
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.godshield.arn
    container_name   = var.app_name
    container_port   = var.container_port
  }

  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200

  depends_on = [aws_lb_listener.https]
}

resource "aws_appautoscaling_target" "godshield" {
  max_capacity       = 20
  min_capacity       = 3
  resource_id        = "service/${aws_ecs_cluster.godshield.name}/${aws_ecs_service.godshield.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "godshield_cpu" {
  name               = "${var.app_name}-cpu-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.godshield.resource_id
  scalable_dimension = aws_appautoscaling_target.godshield.scalable_dimension
  service_namespace  = aws_appautoscaling_target.godshield.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value = 70
  }
}

# ── Network ─────────────────────────────────────────────────────────────

resource "aws_security_group" "alb" {
  name_prefix = "${var.app_name}-alb-"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "tasks" {
  name_prefix = "${var.app_name}-tasks-"
  vpc_id      = var.vpc_id

  # Only the load balancer reaches the containers.
  ingress {
    from_port       = var.container_port
    to_port         = var.container_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lb" "godshield" {
  name               = "${var.app_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids
}

resource "aws_lb_target_group" "godshield" {
  name        = "${var.app_name}-tg"
  port        = var.container_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path                = "/health"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
    timeout             = 5
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.godshield.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.godshield.arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.godshield.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# ── Outputs ─────────────────────────────────────────────────────────────

output "load_balancer_dns" {
  value = aws_lb.godshield.dns_name
}

output "ecr_repository_url" {
  value = aws_ecr_repository.godshield.repository_url
}
