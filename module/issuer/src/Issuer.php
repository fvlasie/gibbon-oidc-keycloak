<?php

namespace Gibbon\Module\OIDCServer\Issuer;

class Issuer
{
    public function __construct(
        private Store $store,
        private string $realmName,
        private string $publicOrigin,
        private string $basePath,
    ) {
    }

    public function issuerUrl(): string
    {
        $realm = $this->store->getRealm($this->realmName);
        if ($realm && !empty($realm['issuerUrl'])) {
            return rtrim($realm['issuerUrl'], '/');
        }

        return rtrim($this->publicOrigin, '/').$this->basePath.'/realms/'.$this->realmName;
    }

    public function handle(): void
    {
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $path = $this->requestPath();

        if ($method === 'OPTIONS') {
            $this->cors();
            http_response_code(204);
            return;
        }

        if ($path === '/test-rp.html' || $path === '/test-rp') {
            $this->serveTestRp();
            return;
        }

        if (preg_match('#^/realms/([^/]+)/\.well-known/openid-configuration$#', $path, $m)) {
            $this->assertRealm($m[1]);
            $this->discovery();
            return;
        }
        if (preg_match('#^/realms/([^/]+)/protocol/openid-connect/certs$#', $path, $m)) {
            $this->assertRealm($m[1]);
            $this->jwks();
            return;
        }
        if (preg_match('#^/realms/([^/]+)/protocol/openid-connect/auth$#', $path, $m)) {
            $this->assertRealm($m[1]);
            $this->authorize($method);
            return;
        }
        if (preg_match('#^/realms/([^/]+)/protocol/openid-connect/token$#', $path, $m)) {
            $this->assertRealm($m[1]);
            $this->token();
            return;
        }
        if (preg_match('#^/realms/([^/]+)/protocol/openid-connect/userinfo$#', $path, $m)) {
            $this->assertRealm($m[1]);
            $this->userinfo();
            return;
        }
        if (preg_match('#^/realms/([^/]+)/protocol/openid-connect/revoke$#', $path, $m)) {
            $this->assertRealm($m[1]);
            $this->revoke();
            return;
        }
        if (preg_match('#^/realms/([^/]+)/protocol/openid-connect/logout$#', $path, $m)) {
            $this->assertRealm($m[1]);
            $this->logout($method);
            return;
        }
        if ($path === '/' || $path === '') {
            $this->home();
            return;
        }

        $this->json(['error' => 'not_found', 'path' => $path], 404);
    }

    private function requestPath(): string
    {
        $uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
        $prefix = rtrim($this->basePath, '/');
        if ($prefix !== '' && str_starts_with($uri, $prefix)) {
            $uri = substr($uri, strlen($prefix)) ?: '/';
        }

        return $uri;
    }

    private function assertRealm(string $name): void
    {
        if ($name !== $this->realmName) {
            $this->json(['error' => 'invalid_realm'], 404);
            exit;
        }
    }

    private function discovery(): void
    {
        $iss = $this->issuerUrl();
        $this->cors();
        $this->json([
            'issuer' => $iss,
            'authorization_endpoint' => $iss.'/protocol/openid-connect/auth',
            'token_endpoint' => $iss.'/protocol/openid-connect/token',
            'userinfo_endpoint' => $iss.'/protocol/openid-connect/userinfo',
            'jwks_uri' => $iss.'/protocol/openid-connect/certs',
            'end_session_endpoint' => $iss.'/protocol/openid-connect/logout',
            'revocation_endpoint' => $iss.'/protocol/openid-connect/revoke',
            'introspection_endpoint' => $iss.'/protocol/openid-connect/token/introspect',
            'response_types_supported' => ['code', 'code id_token'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'token_endpoint_auth_methods_supported' => ['none', 'client_secret_post', 'client_secret_basic'],
            'code_challenge_methods_supported' => ['S256', 'plain'],
            'scopes_supported' => ['openid', 'profile', 'email', 'offline_access', 'roles'],
            'claims_supported' => [
                'sub', 'iss', 'aud', 'exp', 'iat', 'name', 'given_name', 'family_name',
                'preferred_username', 'email', 'email_verified', 'roles',
                'azp', 'typ', 'sid', 'session_state', 'realm_access', 'resource_access',
            ],
        ]);
    }

    private function jwks(): void
    {
        $this->cors();
        $this->json(['keys' => $this->store->listJwks()]);
    }

    private function authorize(string $method): void
    {
        $params = $method === 'POST' ? array_merge($_GET, $_POST) : $_GET;
        $clientId = (string) ($params['client_id'] ?? '');
        $redirectUri = (string) ($params['redirect_uri'] ?? '');
        $state = (string) ($params['state'] ?? '');
        $scope = (string) ($params['scope'] ?? 'openid');
        $nonce = (string) ($params['nonce'] ?? '');
        $challenge = (string) ($params['code_challenge'] ?? '');
        $challengeMethod = (string) ($params['code_challenge_method'] ?? 'plain');
        $responseType = (string) ($params['response_type'] ?? 'code');

        $client = $this->store->getClient($clientId);
        if (!$client || !$this->redirectAllowed($client, $redirectUri)) {
            $this->htmlError('Unknown client or redirect_uri.');
            return;
        }
        if ($responseType !== 'code' && $responseType !== 'code id_token') {
            $this->redirectError($redirectUri, 'unsupported_response_type', $state);
            return;
        }
        if (($client['pkceRequired'] ?? 'Y') === 'Y' && $challenge === '') {
            $this->redirectError($redirectUri, 'invalid_request', $state, 'PKCE required');
            return;
        }

        $session = $this->currentSession();
        if ($method === 'POST' && isset($_POST['username'], $_POST['password'])) {
            $user = $this->store->findUserByUsername((string) $_POST['username']);
            if (!$user || ($user['status'] ?? '') !== 'Full' || !password_verify((string) $_POST['password'], $user['passwordStrong'])) {
                $this->loginForm($params, 'That username or password is not valid, or the account is not Full.');
                return;
            }
            $sessionId = bin2hex(random_bytes(16));
            $this->store->saveSession($sessionId, (int) $user['gibbonPersonID'], time() + 3600);
            $this->setSessionCookie($sessionId);
            $session = ['sessionId' => $sessionId, 'gibbonPersonID' => (int) $user['gibbonPersonID']];
        }

        if (!$session) {
            $this->loginForm($params);
            return;
        }

        $code = $this->randomToken();
        $this->store->saveAuthCode([
            'codeHash' => hash('sha256', $code),
            'gibbonPersonID' => (int) $session['gibbonPersonID'],
            'clientId' => $clientId,
            'redirectUri' => $redirectUri,
            'scope' => $scope,
            'nonce' => $nonce,
            'codeChallenge' => $challenge,
            'codeChallengeMethod' => $challengeMethod,
            'sessionId' => $session['sessionId'],
            'expires' => time() + 120,
        ]);

        $sep = str_contains($redirectUri, '?') ? '&' : '?';
        header('Location: '.$redirectUri.$sep.http_build_query(['code' => $code, 'state' => $state, 'session_state' => $session['sessionId']]));
    }

    private function token(): void
    {
        $this->cors();
        $grant = (string) ($_POST['grant_type'] ?? '');
        if ($grant === 'authorization_code') {
            $this->tokenAuthorizationCode();
            return;
        }
        if ($grant === 'refresh_token') {
            $this->tokenRefresh();
            return;
        }
        $this->json(['error' => 'unsupported_grant_type'], 400);
    }

    private function tokenAuthorizationCode(): void
    {
        $code = (string) ($_POST['code'] ?? '');
        $redirectUri = (string) ($_POST['redirect_uri'] ?? '');
        $clientId = (string) ($_POST['client_id'] ?? $this->basicClientId());
        $verifier = (string) ($_POST['code_verifier'] ?? '');
        $row = $this->store->takeAuthCode(hash('sha256', $code));
        if (!$row || $row['expires'] < time()) {
            $this->json(['error' => 'invalid_grant'], 400);
            return;
        }
        if ($row['clientId'] !== $clientId || $row['redirectUri'] !== $redirectUri) {
            $this->json(['error' => 'invalid_grant'], 400);
            return;
        }
        $client = $this->store->getClient($clientId);
        if (!$client || !$this->clientAuthOk($client)) {
            $this->json(['error' => 'invalid_client'], 401);
            return;
        }
        if (!empty($row['codeChallenge'])) {
            if (!$this->pkceOk($row['codeChallenge'], $row['codeChallengeMethod'], $verifier)) {
                $this->json(['error' => 'invalid_grant', 'error_description' => 'PKCE verification failed'], 400);
                return;
            }
        }
        $this->json($this->issueTokens($row, $client));
    }

    private function tokenRefresh(): void
    {
        $refresh = (string) ($_POST['refresh_token'] ?? '');
        $clientId = (string) ($_POST['client_id'] ?? $this->basicClientId());
        $row = $this->store->takeRefresh(hash('sha256', $refresh));
        if (!$row || $row['expires'] < time() || $row['clientId'] !== $clientId) {
            $this->json(['error' => 'invalid_grant'], 400);
            return;
        }
        $client = $this->store->getClient($clientId);
        if (!$client || !$this->clientAuthOk($client)) {
            $this->json(['error' => 'invalid_client'], 401);
            return;
        }
        $this->json($this->issueTokens($row, $client));
    }

    private function issueTokens(array $row, array $client): array
    {
        $user = $this->store->getUser((int) $row['gibbonPersonID']);
        if (!$user || ($user['status'] ?? '') !== 'Full') {
            $this->json(['error' => 'invalid_grant'], 400);
            exit;
        }
        $realm = $this->store->getRealm($this->realmName);
        $key = $this->store->getActiveKey();
        if (!$key) {
            $this->json(['error' => 'server_error', 'error_description' => 'No signing key'], 500);
            exit;
        }
        $now = time();
        $accessTtl = (int) ($realm['accessTtl'] ?? 300);
        $idTtl = (int) ($realm['idTtl'] ?? 300);
        $refreshTtl = (int) ($realm['refreshTtl'] ?? 2592000);
        $claims = $this->userClaims($user, $client, $row);
        $access = array_merge($claims, [
            'iss' => $this->issuerUrl(),
            'aud' => 'account',
            'exp' => $now + $accessTtl,
            'iat' => $now,
            'nbf' => $now,
            'jti' => bin2hex(random_bytes(16)),
            'azp' => $client['clientId'],
            'typ' => 'Bearer',
            'sid' => $row['sessionId'],
            'session_state' => $row['sessionId'],
            'acr' => '1',
            'allowed-origins' => $this->origins($client),
            'scope' => $row['scope'],
        ]);
        $id = [
            'iss' => $this->issuerUrl(),
            'sub' => $claims['sub'],
            'aud' => $client['clientId'],
            'exp' => $now + $idTtl,
            'iat' => $now,
            'azp' => $client['clientId'],
            'nonce' => $row['nonce'] ?? null,
            'sid' => $row['sessionId'],
            'email' => $claims['email'] ?? null,
            'preferred_username' => $claims['preferred_username'] ?? null,
            'name' => $claims['name'] ?? null,
        ];
        $accessJwt = Jwt::sign($access, $key['privatePem'], $key['kid']);
        $idJwt = Jwt::sign(array_filter($id, fn ($v) => $v !== null), $key['privatePem'], $key['kid']);
        $out = [
            'access_token' => $accessJwt,
            'id_token' => $idJwt,
            'token_type' => 'Bearer',
            'expires_in' => $accessTtl,
            'scope' => $row['scope'],
            'session_state' => $row['sessionId'],
        ];
        if (str_contains($row['scope'], 'offline_access') || str_contains($row['scope'], 'openid')) {
            $refresh = $this->randomToken();
            $this->store->saveRefresh([
                'tokenHash' => hash('sha256', $refresh),
                'gibbonPersonID' => (int) $user['gibbonPersonID'],
                'clientId' => $client['clientId'],
                'scope' => $row['scope'],
                'sessionId' => $row['sessionId'],
                'expires' => $now + $refreshTtl,
            ]);
            $out['refresh_token'] = $refresh;
        }

        return $out;
    }

    private function userClaims(array $user, array $client, array $row): array
    {
        $roles = $this->store->rolesForUser($user);
        $maps = $this->store->listClaimMaps();
        $realmRoles = [];
        $opencloud = [];
        $resource = [];
        foreach ($roles as $role) {
            $realmRoles[] = $role['name'];
            foreach ($maps as $map) {
                if ((int) $map['gibbonRoleID'] !== (int) $role['gibbonRoleID']) {
                    continue;
                }
                if (!empty($map['realmRole'])) {
                    $realmRoles[] = $map['realmRole'];
                }
                if (!empty($map['opencloudRole'])) {
                    $opencloud[] = $map['opencloudRole'];
                }
                if (!empty($map['clientId']) && !empty($map['clientRole'])) {
                    $resource[$map['clientId']]['roles'][] = $map['clientRole'];
                }
            }
        }
        $realmRoles = array_values(array_unique($realmRoles));
        $opencloud = array_values(array_unique($opencloud));

        return [
            'sub' => (string) (int) $user['gibbonPersonID'],
            'preferred_username' => $user['username'],
            'email' => $user['email'] ?? null,
            'email_verified' => !empty($user['email']),
            'given_name' => $user['firstName'] ?? null,
            'family_name' => $user['surname'] ?? null,
            'name' => $user['officialName'] ?: trim(($user['firstName'] ?? '').' '.($user['surname'] ?? '')),
            'roles' => $opencloud ?: $realmRoles,
            'realm_access' => ['roles' => $realmRoles],
            'resource_access' => $resource,
        ];
    }

    private function userinfo(): void
    {
        $this->cors();
        $jwt = $this->bearer();
        if ($jwt === '') {
            $this->json(['error' => 'invalid_token'], 401);
            return;
        }
        $key = $this->store->getActiveKey();
        try {
            $claims = Jwt::verify($jwt, $key['publicJwk']);
        } catch (\Throwable $e) {
            $this->json(['error' => 'invalid_token'], 401);
            return;
        }
        if (($claims['iss'] ?? '') !== $this->issuerUrl() || ($claims['exp'] ?? 0) < time()) {
            $this->json(['error' => 'invalid_token'], 401);
            return;
        }
        $this->json([
            'sub' => $claims['sub'],
            'preferred_username' => $claims['preferred_username'] ?? null,
            'email' => $claims['email'] ?? null,
            'email_verified' => $claims['email_verified'] ?? false,
            'name' => $claims['name'] ?? null,
            'given_name' => $claims['given_name'] ?? null,
            'family_name' => $claims['family_name'] ?? null,
            'roles' => $claims['roles'] ?? [],
            'realm_access' => $claims['realm_access'] ?? ['roles' => []],
        ]);
    }

    private function revoke(): void
    {
        $this->cors();
        $token = (string) ($_POST['token'] ?? '');
        if ($token !== '') {
            $this->store->deleteRefresh(hash('sha256', $token));
        }
        http_response_code(200);
    }

    private function logout(string $method): void
    {
        $params = $method === 'POST' ? $_POST : $_GET;
        $session = $this->currentSession();
        if ($session) {
            $this->store->deleteSession($session['sessionId']);
        }
        setcookie('oidc_sid', '', ['expires' => time() - 3600, 'path' => '/', 'httponly' => true, 'samesite' => 'Lax']);
        $redirect = (string) ($params['post_logout_redirect_uri'] ?? '');
        if ($redirect !== '') {
            header('Location: '.$redirect);
            return;
        }
        $this->html('<h1>Signed out</h1><p>You have been signed out of the Gibbon identity provider.</p>');
    }

    private function home(): void
    {
        $iss = htmlspecialchars($this->issuerUrl(), ENT_QUOTES);
        $this->html(<<<HTML
<h1>Gibbon OIDC Server</h1>
<p>Keycloak-shaped issuer for Gibbon accounts.</p>
<ul>
  <li>Discovery: <a href="{$iss}/.well-known/openid-configuration">{$iss}/.well-known/openid-configuration</a></li>
  <li>Test client: <a href="{$this->basePath}/test-rp.html">OpenCloud-style PKCE login</a></li>
</ul>
<p>Demo accounts (standalone): <code>admin</code>, <code>teacher</code>, <code>student</code> / <code>changeme</code></p>
HTML);
    }

    private function serveTestRp(): void
    {
        $iss = htmlspecialchars($this->issuerUrl(), ENT_QUOTES);
        header('Content-Type: text/html; charset=utf-8');
        echo str_replace('__ISSUER__', $iss, file_get_contents(__DIR__.'/../public/test-rp.html'));
    }

    private function loginForm(array $params, string $error = ''): void
    {
        $q = htmlspecialchars(http_build_query(array_intersect_key($params, array_flip([
            'client_id', 'redirect_uri', 'state', 'scope', 'nonce', 'code_challenge', 'code_challenge_method', 'response_type',
        ]))), ENT_QUOTES);
        $err = $error !== '' ? '<p class="err">'.htmlspecialchars($error, ENT_QUOTES).'</p>' : '';
        $this->html(<<<HTML
<h1>Sign in with Gibbon</h1>
<p>Use your school username and password.</p>
{$err}
<form method="post" action="?{$q}">
  <label>Username <input name="username" autocomplete="username" required></label>
  <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
  <button type="submit">Sign in</button>
</form>
HTML);
    }

    private function currentSession(): ?array
    {
        $sid = $_COOKIE['oidc_sid'] ?? '';
        if ($sid === '') {
            return null;
        }

        return $this->store->getSession($sid);
    }

    private function setSessionCookie(string $sessionId): void
    {
        setcookie('oidc_sid', $sessionId, [
            'expires' => time() + 3600,
            'path' => '/',
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
        $_COOKIE['oidc_sid'] = $sessionId;
    }

    private function redirectAllowed(array $client, string $uri): bool
    {
        $allowed = preg_split('/\s+/', trim((string) $client['redirectUris'])) ?: [];

        return $uri !== '' && in_array($uri, $allowed, true);
    }

    private function origins(array $client): array
    {
        $raw = trim((string) ($client['allowedOrigins'] ?? ''));
        if ($raw === '' || $raw === '*') {
            return ['/*'];
        }

        return preg_split('/\s+/', $raw) ?: [];
    }

    private function pkceOk(string $challenge, string $method, string $verifier): bool
    {
        if ($verifier === '') {
            return false;
        }
        if ($method === 'S256') {
            return hash_equals($challenge, Jwt::b64url(hash('sha256', $verifier, true)));
        }

        return hash_equals($challenge, $verifier);
    }

    private function clientAuthOk(array $client): bool
    {
        if (($client['public'] ?? 'Y') === 'Y') {
            return true;
        }
        $secret = (string) ($_POST['client_secret'] ?? '');
        if ($secret === '' && isset($_SERVER['PHP_AUTH_PW'])) {
            $secret = (string) $_SERVER['PHP_AUTH_PW'];
        }
        $hash = $client['clientSecretHash'] ?? '';

        return $hash !== '' && password_verify($secret, $hash);
    }

    private function basicClientId(): string
    {
        return (string) ($_SERVER['PHP_AUTH_USER'] ?? '');
    }

    private function bearer(): string
    {
        $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (preg_match('/Bearer\s+(\S+)/i', $header, $m)) {
            return $m[1];
        }

        return (string) ($_GET['access_token'] ?? '');
    }

    private function randomToken(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    private function cors(): void
    {
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Headers: Authorization, Content-Type');
        header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    }

    private function json(array $data, int $status = 200): void
    {
        http_response_code($status);
        header('Content-Type: application/json');
        echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    }

    private function html(string $body): void
    {
        header('Content-Type: text/html; charset=utf-8');
        echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Gibbon sign-in</title><style>
          :root { font-family: Georgia, serif; color: #1c1917; background: #f5f1ea; }
          body { max-width: 32rem; margin: 3rem auto; padding: 0 1.25rem; }
          h1 { font-weight: 600; font-size: 1.6rem; }
          label { display: block; margin: 0.75rem 0; }
          input { width: 100%; padding: 0.5rem; font: inherit; }
          button { margin-top: 0.75rem; padding: 0.5rem 1rem; font: inherit; background: #1e3a5f; color: #fff; border: 0; cursor: pointer; }
          .err { color: #9f1239; }
          a { color: #1e3a5f; }
          code { background: #e7e0d4; padding: 0.1rem 0.3rem; }
        </style></head><body>'.$body.'</body></html>';
    }

    private function htmlError(string $message): void
    {
        http_response_code(400);
        $this->html('<h1>Cannot continue</h1><p>'.htmlspecialchars($message, ENT_QUOTES).'</p>');
    }

    private function redirectError(string $redirectUri, string $error, string $state, string $desc = ''): void
    {
        $sep = str_contains($redirectUri, '?') ? '&' : '?';
        $q = ['error' => $error, 'state' => $state];
        if ($desc !== '') {
            $q['error_description'] = $desc;
        }
        header('Location: '.$redirectUri.$sep.http_build_query($q));
    }
}
