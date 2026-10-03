# claude-apps-gateway (Terraform)

A reference deployment of the [Claude apps gateway for AWS](https://aws.amazon.com/blogs/machine-learning/introducing-claude-apps-gateway-for-aws/)
— a self-hosted control plane that centralizes identity, policy,
telemetry, and spend caps for Claude Code and Claude Desktop across your
organization, routing inference to Amazon Bedrock.

Mirrors [Anthropic's own AWS deployment guide](https://code.claude.com/docs/en/claude-apps-gateway-on-aws)
closely — same IAM policies, security group chain, RDS setup, and ECS
task shape — as Terraform. A working example for customer-managed
infrastructure, not a supported production deployment; review and adapt
it before relying on it.

## Why this is a two-phase apply

A single `terraform apply` can't create an empty ECR repository, wait
for a human to build and push an image into it, and then create an ECS
service that needs that image to exist in the same pass — the service
would never reach a steady state. Target the ECR repository first:

```bash
terraform apply -target=aws_ecr_repository.gateway
```

Build and push your image (see [Usage](#usage) below), then run a
normal `terraform apply` — it's a no-op for the repository and creates
everything else, including the ECS service.

## Architecture

- **Amazon ECS on AWS Fargate** running the gateway container
- **Amazon RDS for PostgreSQL** in private subnets, storage-encrypted,
  TLS-only (`rds.force_ssl=1`), holding short-lived sign-in state
- **AWS Secrets Manager** for the JWT signing key, the OIDC client
  secret, and the full Postgres connection string — generated with
  `random_password` and never hardcoded
- **A least-privilege IAM task role** scoped to exactly
  `bedrock:InvokeModel`/`InvokeModelWithResponseStream` on the Claude
  inference-profile and foundation-model ARNs
- **An internal Application Load Balancer**, `ipv4`-only (a dual-stack
  internal ALB publishes public-range AAAA records, which Claude Code's
  `/login` private-network check rejects), TLS 1.3-floor SSL policy,
  3600s idle timeout for streaming
- **An optional `bedrock-runtime` interface VPC endpoint** so inference
  traffic never leaves the AWS network (on by default —
  `create_bedrock_vpc_endpoint = false` to skip)
- **KMS encryption throughout** — a customer-managed key for Secrets
  Manager, the ECR repository, and the ECS log group; RDS storage
  encryption; access logs delivered to a dedicated, encrypted S3 bucket
- **RDS hardening** — Performance Insights, Enhanced Monitoring,
  automatic minor-version upgrades, IAM database authentication enabled
  (available alongside password auth, not replacing it), PostgreSQL log
  export to CloudWatch, and an optional Multi-AZ toggle
- **ECS/ALB hardening** — Container Insights, a read-only root
  filesystem on the gateway container (with a writable `/tmp` via an
  ephemeral volume), ALB deletion protection, and invalid-header
  dropping

## Prerequisites

- A VPC with at least two private subnets in different Availability
  Zones, with outbound internet access via a NAT gateway
- An OIDC identity provider with a web application registered for the
  gateway — redirect URI `https://<gateway-hostname>/oauth/callback`
- A TLS hostname for the gateway and an ACM certificate for it
- The AWS CLI v2 and Docker, installed and authenticated locally
- Claude Code v2.1.195+ downloaded per
  [Install Claude Code](https://code.claude.com/docs/en/setup) — you
  need the native `linux-x64` binary to build into the image

## Usage

```hcl
module "claude_apps_gateway" {
  source = "github.com/DustyStudy/aws-ai-guardrails//terraform/claude-apps-gateway"

  vpc_id                    = "vpc-xxxxxxxx"
  private_subnet_ids        = ["subnet-aaaa", "subnet-bbbb"]
  corporate_cidr            = "10.0.0.0/8"
  acm_certificate_arn       = "arn:aws:acm:us-east-1:123456789012:certificate/xxxx"
  oidc_client_secret_value  = var.idp_client_secret # mark sensitive at the call site too
}
```

```bash
terraform init
terraform apply -target=aws_ecr_repository.gateway

ECR_URI=$(terraform output -raw ecr_repository_url)

cp gateway.yaml.example gateway.yaml
# Fill in every REPLACE_ME: public_url, trusted_proxies,
# oidc.issuer/client_id/allowed_email_domains, upstreams[0].region.

curl -fL --proto '=https' -o rds-global-bundle.pem \
  https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem

aws ecr get-login-password --region <region> \
  | docker login --username AWS --password-stdin "$(echo $ECR_URI | cut -d/ -f1)"

docker build --platform=linux/amd64 -t "${ECR_URI}:v1" .
docker push "${ECR_URI}:v1"

terraform apply -var="container_image_tag=v1"
```

Then alias your gateway hostname to `load_balancer_dns_name` in your
Route 53 private hosted zone, update the OIDC app's redirect URI if you
hadn't finalized it, and push the gateway URL to developer machines via
your MDM's managed settings file — see
[Set the gateway URL](https://code.claude.com/docs/en/claude-apps-gateway#set-the-gateway-url).

## Inputs

| Name | Description | Default |
|---|---|---|
| `name_prefix` | Prefix for all resource names | `claude-gateway` |
| `vpc_id` | VPC to deploy into | — (required) |
| `private_subnet_ids` | At least 2 private subnets, different AZs | — (required) |
| `corporate_cidr` | CIDR allowed to reach the ALB on 443 | — (required) |
| `acm_certificate_arn` | ACM certificate for the gateway hostname | — (required) |
| `oidc_client_secret_value` | Your IdP app's OAuth client secret (sensitive) | — (required) |
| `container_image_tag` | Image tag to deploy. The repository is `IMMUTABLE`, so always pass an explicit versioned tag (e.g. `v1`) | `latest` |
| `desired_count` | Number of gateway tasks | `1` |
| `db_instance_class` | RDS instance class | `db.t4g.micro` |
| `db_allocated_storage_gb` | RDS storage in GB | `20` |
| `enable_deletion_protection` | RDS + ALB deletion protection (a final RDS snapshot is always taken on destroy) | `true` |
| `enable_multi_az` | Enable RDS Multi-AZ - roughly doubles RDS cost | `false` |
| `create_bedrock_vpc_endpoint` | Create the `bedrock-runtime` interface endpoint | `true` |

## Outputs

| Name | Description |
|---|---|
| `ecr_repository_url` | Push your image here (phase 1) |
| `load_balancer_dns_name` | Internal ALB DNS name |
| `ecs_cluster_name` / `ecs_service_name` | ECS resource names |
| `task_definition_arn` | ARN of the registered task definition |
| `jwt_secret_arn` / `oidc_client_secret_arn` / `postgres_url_secret_arn` | Secrets Manager ARNs |
| `database_endpoint` | RDS endpoint address |
| `kms_key_arn` | KMS key encrypting secrets, the ECR repository, and the log group |
| `alb_logs_bucket_name` | S3 bucket holding ALB access logs |

## Notes

- **The gateway never sends telemetry, prompts, or completions to
  Anthropic** unless the Anthropic API is itself a configured upstream —
  this deployment uses Bedrock, so all inference stays inside your AWS
  account's security boundary.
- **Rotating the JWT secret or OIDC client secret** requires a task
  restart to pick up the new value — force a new deployment after
  rotating (`aws ecs update-service --force-new-deployment`).
- **Automatic secret rotation isn't wired up** for any of the four
  secrets in this reference deployment. The DB master password is the
  one with a real, implementable path (AWS's RDS single-user rotation
  Lambda, deployed alongside network access to the database); the JWT
  secret can only be rotated by generating a new value and forcing a new
  ECS deployment; the OIDC client secret requires coordinating with your
  IdP's own admin console, which a Secrets Manager rotation Lambda can't
  do unattended; the Postgres URL secret is a derived string that would
  need regenerating whenever the master password rotates. Each secret's
  `checkov:skip` comment in `main.tf` repeats this.
- **A `gateway.yaml` edit means a rebuild under a new image tag.** The
  config is baked into the image, and the ECR repository's `IMMUTABLE`
  tag setting means an existing tag can't be silently re-pointed at new
  content anyway.
- **Submit Anthropic's one-time Bedrock use-case form** before the first
  invocation, if no one in your account has already — see
  [Claude Code on Amazon Bedrock](https://code.claude.com/docs/en/amazon-bedrock#1-submit-use-case-details).
- This module intentionally omits Route 53 record creation, since hosted
  zone structure varies too much per org to template generically.
- For an EKS-based deployment instead of ECS Fargate, see
  [the source guide's EKS track](https://code.claude.com/docs/en/claude-apps-gateway-on-aws) —
  this repo doesn't include Kubernetes manifests.
- For per-user/per-group spend caps, model allowlists by IdP group, and
  telemetry fan-out, see the
  [configuration reference](https://code.claude.com/docs/en/claude-apps-gateway-config)
  and expand `gateway.yaml` accordingly.
