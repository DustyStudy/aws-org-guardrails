variable "name_prefix" {
  type        = string
  description = "Prefix used for naming all resources created by this module (also the ECR repository, ECS cluster/service, and RDS identifier)."
  default     = "claude-gateway"
}

variable "vpc_id" {
  type        = string
  description = "VPC to deploy the gateway into. Must already have outbound internet access via a NAT gateway."
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "At least two private subnets in different Availability Zones. Used for the ALB, the ECS service, the RDS instance, and (if enabled) the Bedrock VPC endpoint."
}

variable "corporate_cidr" {
  type        = string
  description = "CIDR range allowed to reach the gateway's ALB on 443 (your corporate network / VPN range). Must not be 0.0.0.0/0."

  validation {
    condition     = can(cidrhost(var.corporate_cidr, 0)) && var.corporate_cidr != "0.0.0.0/0"
    error_message = "corporate_cidr must be a valid IPv4 CIDR block and must not be 0.0.0.0/0."
  }
}

variable "acm_certificate_arn" {
  type        = string
  description = "ARN of an ACM certificate (imported or issued via AWS Private CA) for the gateway's internal hostname."
}

variable "container_image_tag" {
  type        = string
  description = "Tag of the gateway image already pushed to this module's ECR repository. The image must exist before the ECS service can start - see this module's README for the two-phase apply. The ECR repository has IMMUTABLE tags, so an existing tag can't be re-pushed: always set an explicit versioned tag (e.g. v1) rather than relying on this default."
  default     = "latest"
}

variable "desired_count" {
  type        = number
  description = "Number of gateway tasks to run. The gateway is stateless; scale horizontally for availability."
  default     = 1
}

variable "db_instance_class" {
  type        = string
  description = "RDS instance class for the gateway's PostgreSQL store."
  default     = "db.t4g.micro"
}

variable "db_allocated_storage_gb" {
  type        = number
  description = "Allocated storage (GB) for the RDS instance."
  default     = 20
}

variable "enable_deletion_protection" {
  type        = bool
  description = "RDS and ALB deletion protection. Set to false only when you intend to destroy the deployment (or for throwaway/test ones). A final RDS snapshot is always taken on destroy regardless of this setting."
  default     = true
}

variable "enable_multi_az" {
  type        = bool
  description = "Enable RDS Multi-AZ. Roughly doubles RDS cost - defaults false to match this reference deployment's db.t4g.micro sizing. Set true for production."
  default     = false
}

variable "oidc_client_secret_value" {
  type        = string
  description = "The OAuth client secret from your IdP's gateway application registration. Stored in Secrets Manager."
  sensitive   = true
}

variable "create_bedrock_vpc_endpoint" {
  type        = bool
  description = "Create an interface VPC endpoint for bedrock-runtime so inference traffic never leaves the AWS network (recommended). Requires PrivateDnsEnabled support in your VPC."
  default     = true
}
