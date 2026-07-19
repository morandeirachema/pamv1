# pamv1 on Kubernetes, as code. Applies the same topology as deploy/k8s
# but parameterized and state-managed (Terraform >= 1.6 / OpenTofu).
#
#   terraform init
#   terraform apply -var master_key=... -var api_key=... -var database_url=...

terraform {
  required_version = ">= 1.6"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.30, < 3.0" # bounded so a provider major bump can't land unreviewed
    }
  }

  # State holds the applied PAM_MASTER_KEY and PAM_API_KEY in cleartext, so it
  # MUST live in an encrypted, access-controlled remote backend — never the
  # default local terraform.tfstate. Configure one before apply, e.g.:
  #
  # backend "s3" {
  #   bucket       = "my-tf-state"
  #   key          = "pamv1/terraform.tfstate"
  #   region       = "eu-west-1"
  #   encrypt      = true
  #   kms_key_id   = "arn:aws:kms:...:key/..."
  #   use_lockfile = true
  # }
}

provider "kubernetes" {
  config_path    = var.kubeconfig
  config_context = var.kube_context
}

resource "kubernetes_namespace" "pam" {
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/name"                 = "pamv1"
      "pod-security.kubernetes.io/enforce"     = "restricted"
    }
  }
}

resource "kubernetes_secret" "pam" {
  metadata {
    name      = "pam-secrets"
    namespace = kubernetes_namespace.pam.metadata[0].name
  }
  data = {
    PAM_MASTER_KEY           = var.master_key
    PAM_API_KEY              = var.api_key
    PAM_BREAK_GLASS_KEY_HASH = var.break_glass_key_hash
    PAM_DATABASE_URL         = var.database_url
  }
}

resource "kubernetes_deployment" "pam" {
  metadata {
    name      = "pam-server"
    namespace = kubernetes_namespace.pam.metadata[0].name
    labels    = { "app.kubernetes.io/name" = "pamv1" }
  }
  spec {
    replicas = var.replicas
    selector {
      match_labels = { "app.kubernetes.io/name" = "pamv1" }
    }
    template {
      metadata {
        labels = { "app.kubernetes.io/name" = "pamv1" }
      }
      spec {
        automount_service_account_token = false
        security_context {
          run_as_non_root = true
          run_as_user     = 65532 # distroless nonroot UID, numeric so runAsNonRoot is verifiable
          run_as_group    = 65532
          fs_group        = 65532 # make the /data volume writable (SSH host key + recordings)
          seccomp_profile {
            type = "RuntimeDefault"
          }
        }
        volume {
          name = "data"
          empty_dir {}
        }
        container {
          name  = "pam-server"
          image = var.image
          port {
            container_port = 8080
            name           = "http"
          }
          port {
            container_port = 2222
            name           = "ssh"
          }
          env_from {
            secret_ref {
              name = kubernetes_secret.pam.metadata[0].name
            }
          }
          env {
            name  = "PAM_SSH_HOST_KEY"
            value = "/data/ssh_host_key"
          }
          env {
            name  = "PAM_RECORDING_DIR"
            value = "/data/recordings"
          }
          volume_mount {
            name       = "data"
            mount_path = "/data"
          }
          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            capabilities {
              drop = ["ALL"]
            }
          }
          readiness_probe {
            http_get {
              path = "/healthz"
              port = "http"
            }
            initial_delay_seconds = 2
            period_seconds        = 5
          }
          liveness_probe {
            http_get {
              path = "/healthz"
              port = "http"
            }
            period_seconds = 15
          }
          resources {
            requests = {
              cpu    = "50m"
              memory = "64Mi"
            }
            limits = {
              memory = "256Mi"
            }
          }
        }
      }
    }
  }
}

resource "kubernetes_service" "pam" {
  metadata {
    name      = "pam-server"
    namespace = kubernetes_namespace.pam.metadata[0].name
    labels    = { "app.kubernetes.io/name" = "pamv1" }
  }
  spec {
    type     = "ClusterIP"
    selector = { "app.kubernetes.io/name" = "pamv1" }
    port {
      name        = "http"
      port        = 8080
      target_port = "http"
    }
    port {
      name        = "ssh"
      port        = 2222
      target_port = "ssh"
    }
  }
}
