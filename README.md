# AtDev Accounts

Servidor central de cuentas, sesiones, API keys y SSO (OAuth 2.0 / OpenID Connect) para los repos y servicios de **AtDev**.

Incluye:

- Registro y login con email + contraseña (hash `scrypt`, nunca se guardan contraseñas en claro).
- Sesiones con cookies `HttpOnly`, `SameSite=Lax`, expiración y revocación por dispositivo.
- Gestión de perfil, cambio de contraseña y borrado de cuenta.
- API keys (`atdev_...`) para llamar a los servicios desde scripts. Solo se muestran una vez.
- Proveedor OIDC completo para conectar OpenWeb Linux y futuros servicios:
  - `authorization_code` + PKCE (`S256`)
  - `refresh_token` con rotación
  - `userinfo`, descubrimiento (`/.well-known/openid-configuration`) y JWKS (RS256)
  - consentimiento y gestión de apps conectadas
- Panel de cuenta en `/account.html`.
- SQLite persistente, un solo contenedor Docker, sin dependencias externas.

## Estructura

```
atdev-accounts/
├── backend/
│   ├── main.py              # App FastAPI, middleware, estáticos
│   ├── config.py            # Configuración por variables de entorno
│   ├── db.py                # SQLite + esquema
│   ├── security.py          # scrypt, tokens, JWT RS256, PKCE
│   ├── deps.py              # Sesión, bearer, admin
│   ├── schemas.py           # Modelos Pydantic
│   ├── oauth_utils.py       # Utilidades OIDC
│   ├── cli.py               # Gestión de clientes OAuth
│   └── routers/             # auth, account, api-keys, admin, oauth
├── tests/test_api.py
├── index.html               # Landing + login/registro
├── account.html             # Panel de cuenta
├── app.js / account.js
├── style.css
├── Dockerfile
├── docker-compose.yml
└── .env.example
```

## Inicio rápido (local)

Requiere Python 3.11+.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
cp .env.example .env
# edita .env, al menos ADMIN_TOKEN
set -a && . ./.env && set +a
.venv/bin/uvicorn backend.main:app --reload
```

Abre http://localhost:8000. La documentación interactiva de la API está en http://localhost:8000/api/docs.

> `DATA_DIR` contiene `atdev.db` y la clave privada RSA de firma. No lo subas al repo.

## Docker / VPS

```bash
cp .env.example .env
# edita .env con tu dominio real, ADMIN_TOKEN y SECURE_COOKIES=true
docker compose up -d --build
```

El volumen `atdev-data` guarda la base de datos y la clave de firma. Haz copia de seguridad de ese volumen.

Detrás de Nginx/Caddy, activa `TRUST_PROXY=true` y `SECURE_COOKIES=true`. El contenedor escucha en `127.0.0.1:8000` si publicas el puerto solo en local:

```yaml
ports:
  - "127.0.0.1:8000:8000"
```

Ejemplo de Caddy:

```
accounts.tudominio.com {
  reverse_proxy 127.0.0.1:8000
}
```

## Configuración

Todas las variables son opcionales salvo `ADMIN_TOKEN` en producción.

| Variable | Por defecto | Descripción |
| --- | --- | --- |
| `APP_ORIGIN` | `http://localhost:8000` | URL pública del servidor |
| `ISSUER` | igual a `APP_ORIGIN` | Emisor OIDC; debe ser estable |
| `DATA_DIR` | `./data` | Base de datos y clave RSA |
| `SECURE_COOKIES` | automático según `APP_ORIGIN` | Cookies solo por HTTPS |
| `TRUST_PROXY` | `false` | Usa `X-Forwarded-For` |
| `ALLOW_REGISTRATION` | `true` | Permite crear cuentas |
| `ADMIN_TOKEN` | vacío | Protege `/api/admin/*` y la CLI |
| `ALLOWED_ORIGINS` | vacío | Orígenes extra permitidos (coma) |
| `SESSION_TTL_DAYS` | `14` | Duración de sesión normal |
| `REMEMBER_TTL_DAYS` | `30` | Duración con “Remember me” |
| `ACCESS_TOKEN_TTL_MINUTES` | `60` | Vida del access token OIDC |
| `REFRESH_TOKEN_TTL_DAYS` | `30` | Vida del refresh token |
| `DEFAULT_CLIENT_*` | ver `.env.example` | Cliente OAuth sembrado al arrancar |
| `SEED_CLIENTS` | vacío | Lista JSON de clientes OAuth adicionales sembrados al arrancar |

`SEED_CLIENTS` acepta un array JSON de clientes que se crean al arrancar si aún no existen. Cada elemento admite `client_id`, `name`, `redirect_uris`, `scopes`, `public` y, para clientes confidenciales, `client_secret`. Es útil en despliegues con disco efímero:

```json
[
  {
    "client_id": "openweb-linux",
    "name": "OpenWeb Linux",
    "redirect_uris": ["https://example.github.io/openweb-linux/oauth/callback"],
    "scopes": ["openid", "profile", "email", "offline_access"],
    "public": true
  }
]
```

## Conectar un servicio por SSO (OIDC)

### 1. Registrar el cliente

Con la CLI (recomendado en el VPS):

```bash
# Cliente público para una web estática (PKCE obligatorio)
.venv/bin/python -m backend.cli create-client \
  --name "OpenWeb Linux" \
  --redirect-uri "https://openweb.tudominio.com/oauth/callback" \
  --scope openid --scope profile --scope email --scope offline_access \
  --public

# Cliente confidencial para un backend
.venv/bin/python -m backend.cli create-client \
  --name "Mi Backend" \
  --redirect-uri "https://api.tudominio.com/auth/callback"
```

O por API (necesita `X-Admin-Token`):

```bash
curl -X POST https://accounts.tudominio.com/api/admin/clients \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "OpenWeb Linux",
    "redirect_uris": ["https://openweb.tudominio.com/oauth/callback"],
    "scopes": ["openid", "profile", "email", "offline_access"],
    "public": true
  }'
```

Guarda el `client_id` y, si es confidencial, el `client_secret` (se muestra solo al crearlo).

### 2. Descubrimiento

```
GET https://accounts.tudominio.com/.well-known/openid-configuration
```

Devuelve `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint` y `jwks_uri`. Cualquier librería OIDC estándar puede configurarse con el issuer.

### 3. Flujo desde una web estática (PKCE)

```js
const config = {
  issuer: "https://accounts.tudominio.com",
  clientId: "openweb-linux-xxxxxx",
  redirectUri: location.origin + "/oauth/callback",
};

function base64url(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function startLogin() {
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(48)));
  sessionStorage.setItem("pkce_verifier", verifier);
  const challenge = base64url(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)))
  );
  const state = base64url(crypto.getRandomValues(new Uint8Array(16)));
  sessionStorage.setItem("oauth_state", state);

  const params = new URLSearchParams({
    response_type: "code",
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: "openid profile email offline_access",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  location.assign(`${config.issuer}/oauth/authorize?${params}`);
}

async function handleCallback() {
  const params = new URLSearchParams(location.search);
  if (params.get("state") !== sessionStorage.getItem("oauth_state")) {
    throw new Error("State mismatch");
  }
  const response = await fetch(`${config.issuer}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: config.clientId,
      code: params.get("code"),
      redirect_uri: config.redirectUri,
      code_verifier: sessionStorage.getItem("pkce_verifier"),
    }),
  });
  const tokens = await response.json();
  // Guarda tokens.access_token / tokens.refresh_token según tu modelo de seguridad.
  const userinfo = await fetch(`${config.issuer}/oauth/userinfo`, {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  }).then((r) => r.json());
  return { tokens, userinfo };
}
```

Para clientes confidenciales, autentica el token endpoint con `client_secret_basic` (cabecera `Authorization: Basic ...`) o `client_secret_post` y verifica el `id_token` contra `jwks_uri`.

## API principal

### Sesión / cuenta

| Método | Ruta | Descripción |
| --- | --- | --- |
| `GET` | `/api/auth/config` | Configuración pública |
| `POST` | `/api/auth/register` | Crear cuenta |
| `POST` | `/api/auth/login` | Iniciar sesión |
| `GET` | `/api/auth/me` | Usuario actual |
| `POST` | `/api/auth/logout` | Cerrar sesión actual |
| `POST` | `/api/auth/logout-all` | Cerrar todas las sesiones |
| `GET` | `/api/account` | Perfil |
| `PATCH` | `/api/account` | Actualizar nombre |
| `POST` | `/api/account/password` | Cambiar contraseña |
| `DELETE` | `/api/account` | Borrar cuenta (body: `{"password": "..."}`) |
| `GET` | `/api/account/sessions` | Sesiones activas |
| `DELETE` | `/api/account/sessions/{id}` | Revocar sesión |
| `DELETE` | `/api/account/sessions?keep_current=true` | Revocar las demás |
| `GET` | `/api/account/connections` | Apps conectadas |
| `DELETE` | `/api/account/connections/{client_id}` | Revocar acceso OAuth |

### API keys

| Método | Ruta | Descripción |
| --- | --- | --- |
| `GET` | `/api/account/api-keys` | Listar |
| `POST` | `/api/account/api-keys` | Crear (devuelve la clave una vez) |
| `DELETE` | `/api/account/api-keys/{id}` | Revocar |

Uso:

```bash
curl https://accounts.tudominio.com/api/account \
  -H "Authorization: Bearer atdev_xxx"
```

### OAuth / OIDC

| Método | Ruta | Descripción |
| --- | --- | --- |
| `GET` | `/oauth/authorize` | Autorización (redirige al login si hace falta) |
| `POST` | `/oauth/authorize/consent` | Aprobar/denegar consentimiento |
| `POST` | `/oauth/token` | Canjear código o refrescar |
| `GET` | `/oauth/userinfo` | Claims del usuario |
| `POST` | `/oauth/revoke` | Revocar refresh token |
| `GET` | `/.well-known/openid-configuration` | Descubrimiento OIDC |
| `GET` | `/.well-known/jwks.json` | Clave pública de firma |

### Administración

Todas requieren `X-Admin-Token: $ADMIN_TOKEN`.

| Método | Ruta | Descripción |
| --- | --- | --- |
| `GET` | `/api/admin/clients` | Listar clientes OAuth |
| `POST` | `/api/admin/clients` | Crear cliente |
| `DELETE` | `/api/admin/clients/{client_id}` | Eliminar cliente |

## Seguridad

- Contraseñas con `scrypt` (N=16384, r=8, p=1) y salt aleatorio.
- Sesiones y API keys se guardan como hash SHA-256; el valor original solo existe en la cookie o en la respuesta de creación.
- Cookies `HttpOnly`, `SameSite=Lax` y `Secure` cuando hay HTTPS.
- Validación de `Origin` en peticiones que modifican estado (protección CSRF).
- Access tokens e ID tokens firmados con RS256; clave privada generada y persistida en `DATA_DIR/keys`.
- PKCE obligatorio para clientes públicos y códigos de autorización de un solo uso (10 minutos).
- Límite de intentos de login: no incluido todavía; se recomienda poner rate limiting en el proxy (Caddy/Nginx/Cloudflare).

Checklist de producción:

1. `APP_ORIGIN` e `ISSUER` con tu dominio HTTPS.
2. `SECURE_COOKIES=true`, `TRUST_PROXY=true`.
3. `ADMIN_TOKEN` largo y aleatorio; nunca lo expongas en el frontend.
4. Backups periódicos de `DATA_DIR` (base de datos + clave RSA).
5. Rate limiting en el proxy para `/api/auth/login` y `/api/auth/register`.

## Tests

```bash
.venv/bin/python -m pytest -q
```

Cubren registro/login, sesiones, API keys, CSRF, borrado de cuenta, flujo OIDC con PKCE, refresh tokens, clientes confidenciales, discovery y JWKS.

## Licencia

Proyecto privado de AtDev. Ajusta la licencia según tus necesidades.
