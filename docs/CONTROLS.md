# NIST SP 800-53 Rev5 mapping

How each guardrail supports a NIST SP 800-53 Rev5 control. A guardrail is
technical enforcement for part of a control. None of them satisfies a
control on its own; each control also needs policy, procedure and evidence.

| Control | Guardrail | Where |
|---------|-----------|-------|
| AC-2 Account Management | No IAM users, access keys or console passwords outside exempt roles; people sign in through Identity Center groups | `core/DenyIamUserCredentials`, `identity-center` |
| AC-3 Access Enforcement | Organization-wide deny statements enforced by Organizations regardless of identity policies | all SCP bundles |
| AC-5 Separation of Duties | Security tooling, logging and protected roles can be changed only by named security roles; workload principals cannot grant themselves more | `core/DenyProtectedRoleChanges`, `security-services`, permissions boundary |
| AC-6 Least Privilege | Boundary caps delegated principals; permission sets require a boundary by default | permissions boundary, `identity-center` |
| AC-6(1) Authorize Access to Security Functions | Only exempt security roles can change CloudTrail, Config, GuardDuty, Security Hub and Access Analyzer | `security-services` |
| AC-6(5) Privileged Accounts | Member account root user denied; organization access role protected | `core/DenyRootUser`, `core/DenyProtectedRoleChanges` |
| AC-6(10) Prohibit Non-privileged Users from Executing Privileged Functions | Delegated principals cannot change Organizations or account settings, remove boundaries or modify roles outside their path | permissions boundary |
| AC-12 Session Termination | Identity Center sessions default to 1 hour, capped at 12 | `identity-center` |
| AU-9 Protection of Audit Information | CloudTrail trails and Config recorders cannot be stopped, deleted or reconfigured by workloads | `security-services/ProtectAuditLogging` |
| AU-12 Audit Record Generation | Audit logging stays on in every account under the target OUs | `security-services/ProtectAuditLogging` |
| CM-5 Access Restrictions for Change | Guardrail roles and the boundary policy are locked against change | `core/DenyProtectedRoleChanges`, `DenyBoundaryPolicyChanges` |
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
