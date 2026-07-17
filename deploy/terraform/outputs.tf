output "namespace" {
  value = kubernetes_namespace.pam.metadata[0].name
}

output "service" {
  description = "In-cluster service host for the portal/API"
  value       = "pam-server.${kubernetes_namespace.pam.metadata[0].name}.svc"
}
