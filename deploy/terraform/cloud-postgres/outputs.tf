output "endpoint" {
  description = "host:port of the RDS instance."
  value       = aws_db_instance.pamv1.endpoint
}

output "database_url" {
  description = "PAM_DATABASE_URL for pam-server (fill the password from your secret store)."
  value       = "postgres://pam:REDACTED@${aws_db_instance.pamv1.endpoint}/pam?sslmode=verify-full"
}
