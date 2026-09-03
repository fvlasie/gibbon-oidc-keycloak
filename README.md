# Gibbon OIDC Server

A Gibbon module that turns your Gibbon site into a **Keycloak-shaped OpenID Connect issuer**. School accounts (`gibbonPerson`) and roles (`gibbonRole`) are the identity source. OpenCloud and other OIDC clients can sign users in with the same usernames and passwords they already use in Gibbon.

There is no second service. The issuer is PHP inside the module and runs on the same PHP-FPM and MySQL as Gibbon.

## What you install

Copy [`module/`](module/) into Gibbon as:

```text
<gibbon>/modules/OIDC Server/
```

Then install **OIDC Server** in System Admin → Manage Modules.

That creates the `oidc*` tables, seeds realm `gibbon`, and registers public clients `web`, `OpenCloudDesktop`, `OpenCloudAndroid`, and `OpenCloudIOS`.

## One web-server rewrite

Gibbon cannot own `/.well-known` through a module hook. Keycloak-compatible apps look up:

```text
https://school.example/realms/gibbon/.well-known/openid-configuration
```

Add the snippet from [`deploy/nginx-realms.conf`](deploy/nginx-realms.conf) or [`deploy/apache-realms.conf`](deploy/apache-realms.conf) so `/realms/` is handled by `modules/OIDC Server/issuer/index.php`.

Set **Issuer URL** in OIDC Server → Manage Realm to that exact origin (including `https`).

## Gibbon metadata in tokens

On every login the issuer reads:

| Gibbon field | Token / UserInfo |
|---|---|
| `gibbonPersonID` | `sub` (stable) |
| `username` | `preferred_username` |
| `email`, names | `email`, `name`, `given_name`, `family_name` |
| `gibbonRoleIDPrimary` + `gibbonRoleIDAll` | `realm_access.roles` (Gibbon role names) |
| Manage Claims mappings | `roles` (OpenCloud) and `resource_access` |

Only people with `status = Full` can sign in.

Keycloak-ish access-token claims also include `azp`, `typ=Bearer`, `sid`, `session_state`, and `acr`.

## OpenCloud

```bash
OC_OIDC_ISSUER=https://school.example/realms/gibbon
OC_EXCLUDE_RUN_SERVICES=idp
PROXY_OIDC_ACCESS_TOKEN_VERIFY_METHOD=jwt
PROXY_OIDC_REWRITE_WELLKNOWN=true
PROXY_USER_OIDC_CLAIM=sub
PROXY_ROLE_ASSIGNMENT_DRIVER=oidc
WEBFINGER_WEB_OIDC_CLIENT_ID=web
WEBFINGER_DESKTOP_OIDC_CLIENT_ID=OpenCloudDesktop
WEBFINGER_ANDROID_OIDC_CLIENT_ID=OpenCloudAndroid
WEBFINGER_IOS_OIDC_CLIENT_ID=OpenCloudIOS
```

Add each OpenCloud redirect URI on the matching client (Manage Clients). Public clients + PKCE only; no client secret.

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
