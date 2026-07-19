output "endpoint" {
  description = "host:port of the RDS instance."
  value       = aws_db_instance.pamv1.endpoint
}

output "database_url" {
  description = "PAM_DATABASE_URL template for pam-server (fill the password from the managed secret below)."
  value       = "postgres://pam:REDACTED@${aws_db_instance.pamv1.endpoint}/pam?sslmode=verify-full"
}

output "master_user_secret_arn" {
  description = "ARN of the AWS Secrets Manager secret holding the RDS master password."
  value       = aws_db_instance.pamv1.master_user_secret[0].secret_arn
}
