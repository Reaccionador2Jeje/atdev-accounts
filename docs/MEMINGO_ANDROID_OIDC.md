# Memingo IDE for Android — AtDev Accounts OIDC

This document records the public OAuth/OIDC client registration used by the Android Memingo IDE.

## Registered client

| Setting | Value |
| --- | --- |
| Client ID | `memingo-ide-android` |
| Client type | Public native application |
| Client secret | None; never embed a secret in the APK |
| Redirect URI | `dev.atdev.memingoide://oauth/callback` |
| Scopes | `openid profile email offline_access` |
| PKCE | Required; use `S256` |

The Render blueprint seeds this client through `SEED_CLIENTS`. The seed is insert-only: it creates the client when it is absent and does not overwrite an existing client with the same ID. If the redirect URI or scopes need changing later, update the existing client through the protected admin API or remove and recreate it deliberately.

## OIDC issuer

- Issuer: `https://atdev-accounts.onrender.com`
- Discovery: `https://atdev-accounts.onrender.com/.well-known/openid-configuration`
- Authorization: `https://atdev-accounts.onrender.com/oauth/authorize`
- Token: `https://atdev-accounts.onrender.com/oauth/token`
- UserInfo: `https://atdev-accounts.onrender.com/oauth/userinfo`
- JWKS: `https://atdev-accounts.onrender.com/.well-known/jwks.json`

The app reads endpoint URLs from discovery rather than hard-coding them throughout the Android client. The Capacitor WebView exchanges the authorization code and requests UserInfo from the native origin; Render's `ALLOWED_ORIGINS` must include `https://localhost`, `capacitor://localhost`, and `http://localhost` for the Android/iOS origins and local development.

## Native app flow

1. Generate a cryptographically random PKCE verifier and a separate random `state`; generate a `nonce` for the OIDC ID token.
2. Compute the SHA-256 PKCE challenge and encode it using Base64 URL-safe encoding without padding.
3. Open the system browser or Custom Tab at the authorization endpoint with:
   - `response_type=code`
   - `client_id=memingo-ide-android`
   - `redirect_uri=dev.atdev.memingoide://oauth/callback`
   - `scope=openid profile email offline_access`
   - `state`, `nonce`, `code_challenge`, and `code_challenge_method=S256`
4. Handle the registered deep link. Reject the callback if `state` does not match the pending login attempt or if an OAuth `error` is returned.
5. Exchange the one-time authorization code at the token endpoint using form encoding, including the same redirect URI and the original `code_verifier`. Do not send a client secret.
6. Validate the ID token signature using the issuer's JWKS, and validate `iss`, `aud`, `exp`, and `nonce` before treating the user as signed in.
7. Never log authorization codes, access tokens, ID tokens, or refresh tokens. The current Memingo mobile client requests only `openid profile email`, keeps the access token in memory, and clears it when the app session is closed. It does not persist refresh tokens; persistent sign-in requires a separately reviewed Android Keystore-backed storage implementation.

## Android callback registration

The Android build script registers the callback intent filter automatically after Capacitor sync. The application must declare an intent filter matching the exact callback URI:

- scheme: `dev.atdev.memingoide`
- host: `oauth`
- path: `/callback`

Use `android:exported="true"` for the activity that receives the browser callback on modern Android versions, and validate the returned `state` in application code. The intent filter only routes the callback; it does not replace OAuth state validation.

## Deployment note

The client and Capacitor CORS origins are present in the repository's Render blueprint configuration. Render must apply the updated blueprint/environment configuration and redeploy before the token exchange from the Android WebView can work. Verify the deployed client with the protected `GET /api/admin/clients` endpoint; never expose the admin token in the Android app or frontend.
