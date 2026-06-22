################################################################################
# environments/prod/main.tf
# Production environment — Multi-AZ, provisioned MSK, HA Vault, large instances
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
    bucket         = "authclaw-terraform-state-us-east-1"
    key            = "env/prod/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "authclaw-terraform-locks"
    encrypt        = true
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "AuthClaw"
      Environment = "prod"
      ManagedBy   = "Terraform"
    }
  }
}

module "vpc" {
  source      = "../../modules/vpc"
  environment = "prod"
  cidr_block  = "10.2.0.0/16"
  azs         = ["${var.aws_region}a", "${var.aws_region}b", "${var.aws_region}c"]
}

module "kms" {
  source      = "../../modules/kms"
  environment = "prod"
}

module "iam" {
  source        = "../../modules/iam"
  environment   = "prod"
  vault_key_arn = module.kms.vault_unseal_key_arn
  app_key_arn   = module.kms.app_key_arn
  db_key_arn    = module.kms.db_key_arn
  cache_key_arn = module.kms.cache_key_arn
}

module "ecs" {
  source                = "../../modules/ecs"
  environment           = "prod"
  vpc_id                = module.vpc.vpc_id
  subnet_ids            = module.vpc.private_app_subnets
  public_subnet_ids     = module.vpc.public_subnets
  execution_role_arn    = module.iam.ecs_task_execution_role_arn
  task_role_arn         = module.iam.ecs_task_role_arn
  cloudmap_namespace_id = module.vpc.cloudmap_namespace_id

  api_task_cpu      = 2048
  api_task_memory   = 4096
  api_desired_count = 3
  api_min_count     = 2
  api_max_count     = 10

  worker_task_cpu    = 1024
  worker_task_memory = 2048
}

module "rds" {
  source                 = "../../modules/rds"
  environment            = "prod"
  vpc_id                 = module.vpc.vpc_id
  subnet_ids             = module.vpc.private_data_subnets
  instance_class         = "db.m6g.large"
  multi_az               = true
  kms_key_id             = module.kms.db_key_arn
  allowed_security_group = module.ecs.security_group_id
  backup_retention_days  = 30
  cloudmap_namespace_id  = module.vpc.cloudmap_namespace_id
}

module "redis" {
  source                   = "../../modules/redis"
  environment              = "prod"
  vpc_id                   = module.vpc.vpc_id
  subnet_ids               = module.vpc.private_data_subnets
  node_type                = "cache.m6g.large"
  num_cache_nodes          = 3
  automatic_failover       = true
  kms_key_id               = module.kms.cache_key_arn
  allowed_security_group   = module.ecs.security_group_id
  snapshot_retention_days  = 7
  cloudmap_namespace_id    = module.vpc.cloudmap_namespace_id
}

module "msk" {
  source                 = "../../modules/msk"
  environment            = "prod"
  vpc_id                 = module.vpc.vpc_id
  subnet_ids             = module.vpc.private_data_subnets
  kms_key_id             = module.kms.app_key_arn
  allowed_security_group = module.ecs.security_group_id
  cloudmap_namespace_id  = module.vpc.cloudmap_namespace_id
  serverless             = false
  broker_instance_type   = "kafka.m5.xlarge"
  number_of_broker_nodes = 3
}

module "vault" {
  source                 = "../../modules/vault"
  environment            = "prod"
  vpc_id                 = module.vpc.vpc_id
  subnet_ids             = module.vpc.private_app_subnets
  vault_task_role_arn    = module.iam.vault_task_role_arn
  execution_role_arn     = module.iam.ecs_task_execution_role_arn
  vault_unseal_key_arn   = module.kms.vault_unseal_key_arn
  vault_unseal_key_id    = module.kms.vault_unseal_key_id
  ecs_cluster_id         = module.ecs.ecs_cluster_id
  cloudmap_namespace_id  = module.vpc.cloudmap_namespace_id
  alb_security_group_id  = module.ecs.alb_security_group_id
  desired_count          = 3
  task_cpu               = 2048
  task_memory            = 4096
}

module "monitoring" {
  source         = "../../modules/monitoring"
  environment    = "prod"
  db_identifier  = "authclaw-prod"
  redis_id       = "authclaw-prod"
  alb_arn_suffix = module.ecs.alb_arn
  sns_email      = var.alert_email
}
