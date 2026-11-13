# NIST SP 800-53 Rev5 mapping

How each guardrail supports a NIST SP 800-53 Rev5 control. A guardrail is
technical enforcement for part of a control. None of them satisfies a
control on its own; each control also needs policy, procedure and evidence.

Each guardrail is one of three kinds, and evidence for a control should say
which:

- **Prevent:** the request is denied before anything changes. The SCP
  bundles, the permissions boundary, `identity-center` and
  `ai-ml-guardrails`.
- **Detect:** something already in place is reported, and nothing is
  changed. `ai-agent-iam-auditor` and `bedrock-cost-guardrails`.
- **Remediate:** a change is detected after the fact and undone.
  `bedrock-logging-enforcement` restores the logging configuration on a
  schedule, so logging can be off until the next run.
  `sagemaker-notebook-exposure` stops an exposed notebook and disables root
  access, but direct internet access cannot be changed in place, so those
  notebooks are kept stopped until someone recreates them.

| Control | Guardrail | Where |
|---------|-----------|-------|
| AC-2 Account Management | No IAM users, access keys or console passwords outside exempt roles; people sign in through Identity Center groups | `core/DenyIamUserCredentials`, `identity-center` |
| AC-2, IA-5 Authenticator Management | No Bedrock API keys, CodeCommit Git credentials or Keyspaces passwords minted or reset on existing IAM users outside exempt roles (opt-in) | `core/DenyServiceSpecificCredentials` |
| AC-2, IA-5 Authenticator Management, SC-5 Denial-of-service Protection | A leaked IAM user access key cannot send mail through SES or be converted into an SES SMTP password (opt-in; listed SMTP users exempt) | `core/DenySesToIamUsers` |
| AC-3, AC-4, SC-7, SA-9, IA-5 Access Enforcement, Information Flow Enforcement, Boundary Protection, External System Services, Authenticator Management | Credentials held by a listed outside vendor work only from the source ranges that vendor publishes, so a credential stolen in a breach of the vendor fails from elsewhere; code an attacker runs on the vendor's own machines is not covered (opt-in) | `core/DenyVendorOffNetwork<Name>` |
| AC-3 Access Enforcement | Organization-wide deny statements enforced by Organizations regardless of identity policies | all SCP bundles |
| AC-3, AC-4, SC-7, SI-7 Access Enforcement, Information Flow Enforcement, Boundary Protection, Software and Information Integrity | Athena query results cannot be read from or written to a default-named result bucket (`aws-athena-query-results-<account-id>-<region>`) owned outside the organization (opt-in) | `data-and-compute/DenyAthenaResultsBucketOutsideOrg` |
| AC-3, AC-4, SC-7, IA-2 Access Enforcement, Information Flow Enforcement, Boundary Protection, Identification and Authentication | KMS keys tagged `guardrails:network-perimeter=true` cannot be used, granted, re-tagged or re-policied except through a VPC endpoint owned by the organization, so stolen credentials cannot call KMS on them from outside; reads through other services such as SSE-KMS S3 objects need that service's perimeter (opt-in) | `data-and-compute/DenyTaggedKmsKeysOffOrgNetwork` |
| AC-4, SC-7, SA-9(5), CM-7 Information Flow Enforcement, Boundary Protection, Processing and Storage Location, Least Functionality | Bedrock calls cannot route through global cross-Region inference profiles to Regions outside the data boundary (opt-in) | `ai-ml-guardrails/deny-bedrock-global-cross-region-inference` |
| AC-5 Separation of Duties | Security tooling, logging and protected roles can be changed only by named security roles; workload principals cannot grant themselves more | `core/DenyProtectedRoleChanges`, `security-services`, permissions boundary |
| AC-6 Least Privilege | Boundary caps delegated principals; permission sets require a boundary by default | permissions boundary, `identity-center` |
| AC-6, SC-7 Least Privilege, Boundary Protection | Instances launch with an IMDS hop limit of 1, so bridge-networked containers cannot fetch the instance role's credentials (opt-in; host-networked containers and launches by service-linked roles are not covered) | `data-and-compute/RequireImdsHopLimitOne` |
| AC-6(1) Authorize Access to Security Functions | Only exempt security roles can change CloudTrail, Config, GuardDuty, Security Hub and Access Analyzer | `security-services` |
| AC-6(5) Privileged Accounts | Member account root user denied; organization access role protected | `core/DenyRootUser`, `core/DenyProtectedRoleChanges` |
| AC-6(10) Prohibit Non-privileged Users from Executing Privileged Functions | Delegated principals cannot change Organizations or account settings, remove boundaries or modify roles outside their path | permissions boundary |
| AC-12 Session Termination | Identity Center sessions default to 1 hour, capped at 12 | `identity-center` |
| AU-9 Protection of Audit Information | CloudTrail trails and Config recorders cannot be stopped, deleted or reconfigured by workloads | `security-services/ProtectAuditLogging` |
| AU-12 Audit Record Generation | Audit logging stays on in every account under the target OUs | `security-services/ProtectAuditLogging` |
| CM-5 Access Restrictions for Change | Guardrail roles, their prefix-named customer managed policies and the boundary policy are locked against change | `core/DenyProtectedRoleChanges`, `core/DenyProtectedPolicyChanges`, `DenyBoundaryPolicyChanges` |
| CM-6 Configuration Settings | IMDSv2 required at launch and locked afterwards | `data-and-compute` |
| CM-7 Least Functionality | Regional services limited to approved regions | `region-restriction` |
| SC-7 Boundary Protection | Account-level S3 Block Public Access cannot be turned off | `data-and-compute/ProtectAccountPublicAccessBlock` |
| SC-28 Protection of Information at Rest | EBS encryption by default cannot be disabled | `data-and-compute/ProtectEbsDefaultEncryption` |
| SI-4 System Monitoring | GuardDuty, Security Hub and Access Analyzer cannot be disabled or muted with suppression filters | `security-services/ProtectThreatDetection` |

## Not covered

- Turning the services on. These guardrails keep CloudTrail, Config,
  GuardDuty and Security Hub from being turned off; enabling them
  organization-wide is a separate step.
- Data perimeter controls (resource control policies). See the roadmap in
  [DESIGN.md](DESIGN.md#roadmap).
- Evidence collection. The SCP and boundary JSON and the Terraform state are
  the configuration evidence; collecting it on a schedule is out of scope.
