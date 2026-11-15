# AtDev Accounts and Walletie identity roadmap

AtDev Accounts provides OAuth 2.0 / OpenID Connect with RS256 signing, discovery, and JWKS. It is the intended direction for shared AtDev SSO, but Walletie V1 does not currently accept its OIDC tokens.

## Current compatibility

- Walletie V1 accepts AtDev Cloud HS256 bearer tokens only.
- AtDev Accounts issues tokens from its own identity database and OIDC issuer.
- These token formats and account stores are not interchangeable.
- Do not send an AtDev Accounts token to Walletie until issuer, audience, signature, and subject validation are implemented there.

## Required migration work

1. Choose AtDev Accounts as the canonical issuer only after reviewing all existing product identity systems.
2. Define an immutable canonical subject and stable issuer.
3. Design explicit linking for existing AtDev Cloud and Joynexa accounts.
4. Never link accounts by matching email addresses alone.
5. Add Walletie RS256/JWKS validation, exact issuer and audience checks, expiry checks, and key rotation support.
6. Migrate existing wallet ownership with a verified mapping and preserve every transaction.
7. Add tests for invalid tokens and account-linking conflicts.

Do not remove Walletie's current D1 foreign key or change wallet owner IDs before the mapping migration is designed and tested.
