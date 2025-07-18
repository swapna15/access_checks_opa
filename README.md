# Role-Based Access Control Policy for S3 Bucket Access

## Overview

This repository contains an Open Policy Agent (OPA) policy that enforces access to S3 buckets **only** if the user's role is `"st-access-role"`. It supports AWS IAM style inputs as well as Azure AD style role claims.

---

## Policy Behavior

- Allows access if and only if:
  - `input.user.role` equals `"st-access-role"`, or
  - `"st-access-role"` is present in `input.identity.claims.roles`.

- Denies access by default for all other cases.

---

## Edge Cases and Potential Policy Bypass

1. **Missing or malformed role claims**  
   - If the input does not contain `user.role` or `identity.claims.roles`, the policy denies access by default.  
   - Ensure that identity tokens or requests always include valid role claims.

2. **Role case sensitivity**  
   - The policy performs exact case-sensitive matching. Role name variations in case (`ST-ACCESS-ROLE`) will cause denial.  
   - Recommend enforcing normalized role names in upstream identity providers.

3. **Multiple roles with similar names**  
   - The policy matches roles exactly. Roles such as `"st-access-role-admin"` will **not** be matched.  
   - Beware of substring or prefix-based matching risks if policy is modified.

4. **Input tampering**  
   - If the input to the policy is tampered with (e.g., missing roles, spoofed roles), access might be incorrectly granted or denied.  
   - Strong input validation and trusted identity sources are essential.

5. **Token freshness and expiration**  
   - This policy does not validate token expiry or session validity.  
   - Token validation and freshness checks must be enforced before invoking this policy.

6. **Action and resource granularity**  
   - The policy currently only checks roles, not specific actions or resources beyond the input JSON fields.  
   - Further enhancement can restrict permissions per S3 bucket ARN or specific actions.

---

## Logging and Monitoring for Policy Enforcement

- **OPA Audit Logs**  
  - Enable OPA audit logging in your environment to record all policy evaluation requests and decisions.  
  - Logs should capture input context (with sensitive data redacted) and allow/deny outcomes.

- **Custom Tracing**  
  - Use OPA's `trace` function in policy development to debug or monitor policy decision paths.

- **Integration with SIEM**  
  - Forward OPA audit logs to a Security Information and Event Management (SIEM) system for alerting on denied or anomalous requests.

- **Metrics Export**  
  - Export OPA metrics to monitoring systems (Prometheus, Datadog) to track policy hits, allows, and denies.

- **Alerting**  
  - Configure alerts for unusual spikes in denials or unexpected allows.

---

## Assumptions

- Input to the policy is **trusted** and comes from a validated identity provider or request authenticator.  
- Role claims are **accurately propagated** from identity tokens or request metadata.  
- Role names are consistently cased and normalized across identity providers.  
- Token expiration and session management are handled outside this policy scope.  
- The policy enforces access **at the API gateway, authorization middleware, or service mesh level**, prior to resource access.

---

## Running Tests

Use [OPA](https://www.openpolicyagent.org/docs/latest/#running-tests) to run tests:

```bash
opa test -v .