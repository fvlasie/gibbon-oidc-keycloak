# Gibbon OIDC Server

A Gibbon module that turns your Gibbon site into a **Keycloak-shaped OpenID Connect issuer**. School accounts (`gibbonPerson`) and roles (`gibbonRole`) are the identity source. Any client that can talk to Keycloak’s OIDC endpoints can sign users in with the same usernames and passwords they already use in Gibbon.

There is no second service. The issuer is PHP inside the module and runs on the same PHP-FPM and MySQL as Gibbon.

## What you install

Copy [`module/`](module/) into Gibbon as:

```text
<gibbon>/modules/OIDC Server/
```

Then install **OIDC Server** in System Admin → Manage Modules. That is what creates the `oidc*` tables (copying files into `modules/` is not enough).

If the module is already listed as installed but the tables are missing, use **Update** to 1.0.01, or hit the issuer once so it can create them.

Clients are not pre-registered: add each application under **Manage Clients**.

## One web-server rewrite

Gibbon cannot own `/.well-known` through a module hook. Keycloak-compatible apps look up:

```text
https://school.example/realms/gibbon/.well-known/openid-configuration
```

Add the snippet from [`deploy/nginx-realms.conf`](deploy/nginx-realms.conf) or [`deploy/apache-realms.conf`](deploy/apache-realms.conf) so `/realms/` is handled by `modules/OIDC Server/issuer/index.php`.

Set **Issuer URL** in OIDC Server → Manage Realm to that exact origin (including `https`).

## Connect any Keycloak-compatible app

In the application, set the issuer / authority to the discovery URL’s issuer (no trailing slash):

```text
https://school.example/realms/gibbon
```

Typical Keycloak paths this module implements:

| Use | Path |
|---|---|
| Discovery | `{issuer}/.well-known/openid-configuration` |
| Authorization | `{issuer}/protocol/openid-connect/auth` |
| Token | `{issuer}/protocol/openid-connect/token` |
| UserInfo | `{issuer}/protocol/openid-connect/userinfo` |
| JWKS | `{issuer}/protocol/openid-connect/certs` |
| Logout | `{issuer}/protocol/openid-connect/logout` |
| Revoke | `{issuer}/protocol/openid-connect/revoke` |

In **Manage Clients**, create a client whose `client_id` matches the app:

- **Public + PKCE** for SPAs and native apps (no secret).
- **Confidential** for server-side apps (`client_secret_post` or HTTP Basic).

Add every redirect URI the app will use, one per line (exact match).

Supported grants: `authorization_code`, `refresh_token`. Signing: RS256. Only people with Gibbon `status = Full` can sign in.

## Gibbon metadata in tokens

On every login the issuer reads:

| Gibbon field | Token / UserInfo |
|---|---|
| `gibbonPersonID` | `sub` (stable) |
| `username` | `preferred_username` |
| `email`, names | `email`, `name`, `given_name`, `family_name` |
| `gibbonRoleIDPrimary` + `gibbonRoleIDAll` | `realm_access.roles` (Gibbon role names) |
| Manage Claims mappings | optional `roles` array and `resource_access` |

Keycloak-ish access-token claims also include `azp`, `typ=Bearer`, `sid`, `session_state`, and `acr`. Point the app at `sub`, `preferred_username`, `realm_access.roles`, or the flat `roles` claim, depending on what it expects.

## Standalone preview (this repo)

No Gibbon install is required to try the protocol:

```bash
export OIDC_STANDALONE=1
export OIDC_PUBLIC_ORIGIN=http://127.0.0.1:43180
php -S 0.0.0.0:43180 -t module/issuer module/issuer/router.php
```

Open [http://127.0.0.1:43180/test-rp.html](http://127.0.0.1:43180/test-rp.html). Demo users: `admin`, `teacher`, `student` / `changeme`.

```bash
php tests/OidcFlowTest.php
```

## Not included

Keycloak Admin REST, SAML, device grant, CIBA, Gibbon MFA on the authorize page, and year-group or house claims (roles and profile only in v1).
