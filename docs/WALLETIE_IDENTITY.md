# AtDev Accounts and Walletie identity

AtDev Accounts is the target OpenID Connect identity provider for the AtDev ecosystem. Walletie V1 currently validates AtDev Cloud HS256 access tokens and checks the corresponding user in the shared AtDev Cloud D1 database.

These identities are **not interchangeable today**:

- AtDev Cloud uses its existing D1 user IDs and HS256 session tokens.
- AtDev Accounts uses its own SQLite user store and RS256 OIDC tokens with issuer, audience, scope, and JWKS validation.
- Matching email addresses do not prove that two accounts belong to the same person. Do not silently merge accounts by email.

## Safe integration sequence

1. Keep AtDev Cloud JWT validation as-is until a migration is deliberately implemented.
2. Define an explicit account-linking flow in which the user authenticates to both providers and confirms the link.
3. Store a stable mapping between the AtDev Accounts subject and the canonical Walletie owner ID, with uniqueness constraints and an audit trail.
4. Add OIDC issuer/JWKS validation to Walletie only after the canonical subject and migration behavior are specified.
5. Test existing accounts, revoked sessions, duplicate links, account deletion, and rollback before switching identity providers.

Never copy private signing keys between services, accept an ID token as an access token, or trust an unverified JWT payload. Keep the existing login systems working during the migration.

Walletie credits are virtual only and must remain independent of account authentication or access to core AtDev products.
