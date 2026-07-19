variable "name" {
  description = "Name/identifier for the RDS instance."
  type        = string
  default     = "pamv1-pg"
}

variable "instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t3.small"
}

variable "allocated_storage" {
  description = "Allocated storage in GiB."
  type        = number
  default     = 20
}

variable "subnet_group_name" {
  description = "DB subnet group placing the instance in private subnets."
  type        = string
}

variable "security_group_ids" {
  description = "Security groups permitting 5432 only from the pamv1 workloads."
  type        = list(string)
}
