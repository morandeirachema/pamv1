variable "kubeconfig" {
  description = "Path to kubeconfig"
  type        = string
  default     = "~/.kube/config"
}

variable "kube_context" {
  description = "Kubeconfig context to use (null = current)"
  type        = string
  default     = null
}

variable "namespace" {
  type    = string
  default = "pamv1"
}

variable "image" {
  description = "pam-server container image"
  type        = string
  default     = "ghcr.io/morandeirachema/pamv1:latest"
}

variable "replicas" {
  type    = number
  default = 1
}

variable "master_key" {
  description = "Vault master key (PAM_MASTER_KEY)"
  type        = string
  sensitive   = true
}

variable "api_key" {
  description = "Admin API key (PAM_API_KEY)"
  type        = string
  sensitive   = true
}

variable "break_glass_key_hash" {
  description = "SHA-256 hex of the sealed break-glass key (empty disables)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "database_url" {
  description = "PostgreSQL URL (PAM_DATABASE_URL)"
  type        = string
  sensitive   = true
}
