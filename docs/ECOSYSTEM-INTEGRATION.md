# AtDev Accounts — Ecosystem Integration

Status: planning document. Existing login, session and OIDC behavior is not changed by this file.

## Identity boundary
AtDev Accounts is intended to provide identity, sessions, API keys and OIDC for compatible AtDev services. Each integrating application must document whether it uses AtDev Accounts directly or retains its existing account store.

## OIDC integration checklist
- Validate issuer, audience, signature and allowed algorithms.
- Validate state and PKCE for authorization-code flows.
- Validate nonce where required by the OIDC flow.
- Map stable OIDC subject IDs; do not assume email is permanent.
- Define account-linking and duplicate-account behavior.
- Rotate and cache JWKS safely; handle key rollover.
- Define logout, expiry, refresh-token rotation and revocation.
- Keep client secrets and signing keys server-side.

## Service onboarding
1. Register a client with minimum required redirect URIs.
2. Use authorization code with PKCE for public clients.
3. Request only necessary scopes.
4. Test invalid issuer/audience, expired tokens, revoked sessions and account-linking edge cases.
5. Document fallback behavior if the identity provider is unavailable.

Do not migrate existing AtDev Cloud or Joynexa accounts until IDs, password compatibility, session invalidation and rollback are explicitly tested.