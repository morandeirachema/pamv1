# Example Terraform module: a cloud-managed PostgreSQL for pamv1 (AWS RDS).
#
# This is a standalone example (not applied by the root module). Adapt it to your
# provider — the pamv1 contract is only: a TLS-reachable PostgreSQL 14+ database
# and a PAM_DATABASE_URL with sslmode=verify-full. Swap aws_db_instance for
# google_sql_database_instance / azurerm_postgresql_flexible_server as needed.
#
#   terraform -chdir=deploy/terraform/cloud-postgres init
#   terraform -chdir=deploy/terraform/cloud-postgres apply
#
# The master password is generated and stored by RDS in AWS Secrets Manager
# (manage_master_user_password), so none is passed on the command line.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

resource "aws_db_instance" "pamv1" {
  identifier     = var.name
  engine         = "postgres"
  engine_version = "17"
  instance_class = var.instance_class

  db_name  = "pam"
  username = "pam"
  # RDS generates and rotates the master password into AWS Secrets Manager, so it
  # never lands in Terraform state, CLI history, or a tfvars file. pam-server
  # reads it from that managed secret (see outputs.tf).
  manage_master_user_password = true

  allocated_storage       = var.allocated_storage
  storage_encrypted       = true
  publicly_accessible     = false # never expose the vault's database to the internet
  multi_az                = true  # HA: standby in another AZ with automatic failover
  backup_retention_period = 30
  deletion_protection     = true

  # Force TLS; pamv1 connects with sslmode=verify-full.
  parameter_group_name = aws_db_parameter_group.pamv1.name

  db_subnet_group_name   = var.subnet_group_name
  vpc_security_group_ids = var.security_group_ids

  skip_final_snapshot = false
  final_snapshot_identifier = "${var.name}-final"
}

resource "aws_db_parameter_group" "pamv1" {
  name   = "${var.name}-pg17"
  family = "postgres17"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
}
