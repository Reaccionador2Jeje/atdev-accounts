# AtDev Billing compatibility — AtDev Accounts

**Status:** design note only. Authentication and account recovery remain free and must not depend on a paid subscription.

## Hybrid model

AtDev Accounts is shared identity infrastructure. Do not charge end users to register, sign in, recover an account, or export/delete their account data. Optional future managed-identity services may be offered to organizations operating their own applications, such as higher tenant quotas, audit exports, or managed support, once implemented.

## Proposed organization tiers (CLP/month; exploratory)

| Plan | Reference price | Scope |
| --- | ---: | --- |
| Community | $0 | Core identity service and self-hosting |
| Managed Starter | $990 | Future hosted tenant quota and basic audit view |
| Managed Team | $1,990 | Future higher tenant quotas and team administration |

These are placeholders, not available products. Pricing must reflect identity infrastructure, security operations, support, and compliance costs.

## Security boundaries

- Billing must never determine whether a user can access account recovery or security settings.
- Keep authentication credentials and password hashes inside the existing identity service.
- Billing stores only opaque customer/subscription references and entitlement metadata.
- Do not expose payment state to unauthenticated endpoints.
- Use server-side authorization and tenant-scoped quotas.

No checkout is active. Any real-money launch requires an adult account owner's review of provider eligibility and legal/tax obligations.
