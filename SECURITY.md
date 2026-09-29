# Security policy

## Reporting a vulnerability

Please report security problems through GitHub's private vulnerability
reporting ("Report a vulnerability" on the Security tab), not in a public
issue. Include the module, the rendered policy statement if relevant, and
the request that the guardrail should have denied or allowed.

## Scope

In scope: a guardrail that fails to deny what its documentation says it
denies, a way to escape the permissions boundary, or a module input that
silently weakens a policy.

Out of scope: behavior that AWS documents for SCPs in general, such as SCPs
not applying to the management account or to service-linked roles.
