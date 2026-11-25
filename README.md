# IAM Directory Federation Guard

Enterprise Identity & Access Management (IAM) token validation, directory synchronization, and role entitlement reconciliation for federated cloud environments.

## Architecture

- **Token Introspection & Policy Guard**: Validates OAuth2/OIDC token claims (issuer, audience, expiry, scopes, nonces) with zero external network blocking.
- **Directory Group & Attribute Reconciliation**: Reconciles user identities and group memberships across LDAP/SCIM directories and cloud workload entitlements.
- **Session Lifecycle & Backchannel Invalidation**: Manages SSO session state transitions and session revocation propagation.

## Getting Started

```bash
pip install -e ".[dev]"
pytest -v
```
