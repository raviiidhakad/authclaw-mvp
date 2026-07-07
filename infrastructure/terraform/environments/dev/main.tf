################################################################################
# environments/dev/main.tf
# Development environment — cost-optimised, MSK Serverless, single-AZ RDS
################################################################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
  backend "s3" {
    bucket         = "authclaw-terraform-state-ap-south-1"
    key            = "env/dev/terraform.tfstate"
    region         = "ap-south-1"
    dynamodb_table = "authclaw-terraform-locks"
    encrypt        = true
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "AuthClaw"
      Environment = "dev"
      ManagedBy   = "Terraform"
    }
  }
}

module "vpc" {
  source      = "../../modules/vpc"
  environment = "dev"
  cidr_block  = "10.0.0.0/16"
  azs         = ["${var.aws_region}a", "${var.aws_region}b"]
}

module "kms" {
  source      = "../../modules/kms"
  environment = "dev"
}

module "iam" {
  source        = "../../modules/iam"
  environment   = "dev"
  vault_key_arn = module.kms.vault_unseal_key_arn
  app_key_arn   = module.kms.app_key_arn
  db_key_arn    = module.kms.db_key_arn
  cache_key_arn = module.kms.cache_key_arn
}

module "ecs" {
  source                = "../../modules/ecs"
  environment           = "dev"
  vpc_id                = module.vpc.vpc_id
  subnet_ids            = module.vpc.private_app_subnets
  public_subnet_ids     = module.vpc.public_subnets
  execution_role_arn    = module.iam.ecs_task_execution_role_arn
  task_role_arn         = module.iam.ecs_task_role_arn
  cloudmap_namespace_id = module.vpc.cloudmap_namespace_id

  api_task_cpu      = 512
  api_task_memory   = 1024
  api_desired_count = 1
  api_min_count     = 1
  api_max_count     = 3

  worker_task_cpu    = 256
  worker_task_memory = 512
}

module "rds" {
  source                 = "../../modules/rds"
  environment            = "dev"
  vpc_id                 = module.vpc.vpc_id
  subnet_ids             = module.vpc.private_data_subnets
  instance_class         = "db.t4g.micro"
  multi_az               = false
  kms_key_id             = module.kms.db_key_arn
  allowed_security_group = module.ecs.security_group_id
  backup_retention_days  = 7
  cloudmap_namespace_id  = module.vpc.cloudmap_namespace_id
}

module "redis" {
  source                  = "../../modules/redis"
  environment             = "dev"
  vpc_id                  = module.vpc.vpc_id
  subnet_ids              = module.vpc.private_data_subnets
  node_type               = "cache.t4g.micro"
  num_cache_nodes         = 1
  automatic_failover      = false
  kms_key_id              = module.kms.cache_key_arn
  allowed_security_group  = module.ecs.security_group_id
  snapshot_retention_days = 7
  cloudmap_namespace_id   = module.vpc.cloudmap_namespace_id
}

module "msk" {
  source                 = "../../modules/msk"
  environment            = "dev"
  vpc_id                 = module.vpc.vpc_id
  subnet_ids             = module.vpc.private_data_subnets
  kms_key_id             = module.kms.app_key_arn
  allowed_security_group = module.ecs.security_group_id
  cloudmap_namespace_id  = module.vpc.cloudmap_namespace_id
  serverless             = true # Dev uses MSK Serverless
}

module "vault" {
  source                = "../../modules/vault"
  environment           = "dev"
  vpc_id                = module.vpc.vpc_id
  subnet_ids            = module.vpc.private_app_subnets
  vault_task_role_arn   = module.iam.vault_task_role_arn
  execution_role_arn    = module.iam.ecs_task_execution_role_arn
  vault_unseal_key_arn  = module.kms.vault_unseal_key_arn
  vault_unseal_key_id   = module.kms.vault_unseal_key_id
  ecs_cluster_id        = module.ecs.ecs_cluster_id
  cloudmap_namespace_id = module.vpc.cloudmap_namespace_id
  alb_security_group_id = module.ecs.alb_security_group_id
  desired_count         = 1
  task_cpu              = 512
  task_memory           = 1024
}

module "monitoring" {
  source                           = "../../modules/monitoring"
  environment                      = "dev"
  db_identifier                    = "authclaw-dev"
  redis_id                         = "authclaw-dev"
  alb_arn_suffix                   = module.ecs.alb_arn_suffix
  sns_email                        = var.alert_email
  alb_target_group_arn_suffix      = module.ecs.api_target_group_arn_suffix
  api_log_group_name               = module.ecs.api_log_group_name
  audit_worker_log_group_name      = module.ecs.audit_worker_log_group_name
  security_worker_log_group_name   = module.ecs.security_worker_log_group_name
  reconciler_worker_log_group_name = module.ecs.reconciler_worker_log_group_name
}
