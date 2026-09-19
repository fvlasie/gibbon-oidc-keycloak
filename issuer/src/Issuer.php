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
        if ($path === '/' || $path === '' || $this->isFrontControllerPath($path)) {
            $this->home();
            return;
        }

        $this->json(['error' => 'not_found', 'path' => $path], 404);
    }

    private function requestPath(): string
    {
        $fromLine = $this->pathFromRequestLine();
        if ($fromLine !== null) {
            return $this->stripBasePath($fromLine);
        }

        $candidates = [
            $_SERVER['REDIRECT_OIDC_REQUEST_URI'] ?? '',
            $_SERVER['OIDC_REQUEST_URI'] ?? '',
            $_SERVER['REQUEST_URI'] ?? '',
            $_SERVER['REDIRECT_URL'] ?? '',
            $_SERVER['REDIRECT_REQUEST_URI'] ?? '',
        ];
        $uri = '/';
        foreach ($candidates as $candidate) {
            $path = $this->normalizePath((string) $candidate);
            if ($path !== '' && str_contains($path, '/realms/')) {
                return $this->stripBasePath($path);
            }
            if ($uri === '/' && $path !== '') {
                $uri = $path;
            }
        }

        return $this->stripBasePath($uri);
    }

    private function pathFromRequestLine(): ?string
    {
        $line = (string) ($_SERVER['THE_REQUEST'] ?? '');
        if (!preg_match('#^[A-Z]+\s+(\S+)#', $line, $m)) {
            return null;
        }
        $path = $this->normalizePath($m[1]);
        if ($path !== '' && str_contains($path, '/realms/')) {
            return $path;
        }

        return null;
    }

    private function normalizePath(string $candidate): string
    {
        $path = parse_url($candidate, PHP_URL_PATH);
        if (!is_string($path) || $path === '') {
            return '';
        }

        return rawurldecode($path);
    }

    private function stripBasePath(string $uri): string
    {
        $prefix = rtrim($this->basePath, '/');
        if ($prefix !== '' && str_starts_with($uri, $prefix)) {
            return substr($uri, strlen($prefix)) ?: '/';
        }

        return $uri;
    }

    private function isFrontControllerPath(string $path): bool
    {
        return str_contains($path, '/issuer/index.php') || str_ends_with($path, '/issuer');
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
            if (!$user || ($user['status'] ?? '') !== 'Full' || !$this->passwordOk($user, (string) $_POST['password'])) {
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
        $rolesClaim = [];
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
                $extra = $map['rolesClaim'] ?? '';
                if ($extra !== '') {
                    $rolesClaim[] = $extra;
                }
                if (!empty($map['clientId']) && !empty($map['clientRole'])) {
                    $resource[$map['clientId']]['roles'][] = $map['clientRole'];
                }
            }
        }
        $realmRoles = array_values(array_unique($realmRoles));
        $rolesClaim = array_values(array_unique($rolesClaim));

        return [
            'sub' => (string) (int) $user['gibbonPersonID'],
            'preferred_username' => $user['username'],
            'email' => $user['email'] ?? null,
            'email_verified' => !empty($user['email']),
            'given_name' => $user['firstName'] ?? null,
            'family_name' => $user['surname'] ?? null,
            'name' => $user['officialName'] ?: trim(($user['firstName'] ?? '').' '.($user['surname'] ?? '')),
            'roles' => $rolesClaim ?: $realmRoles,
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
  <li>Test client: <a href="{$this->basePath}/test-rp.html">PKCE authorization-code login</a></li>
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
        $err = $error !== '' ? '<div class="alert error">'.htmlspecialchars($error, ENT_QUOTES).'</div>' : '';
        $continue = $this->continueLabel((string) ($params['redirect_uri'] ?? ''));
        $this->html(<<<HTML
<h1>Login</h1>
<p class="lede">Use your Gibbon username and password{$continue}.</p>
{$err}
<form method="post" action="?{$q}">
  <label for="username">Username</label>
  <input id="username" name="username" autocomplete="username" required autofocus>
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="current-password" required>
  <button type="submit">Login</button>
</form>
HTML);
    }

    private function continueLabel(string $redirectUri): string
    {
        $host = parse_url($redirectUri, PHP_URL_HOST);
        if (!is_string($host) || $host === '') {
            return '';
        }

        return ' to continue to '.htmlspecialchars($host, ENT_QUOTES);
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

    private function passwordOk(array $user, string $password): bool
    {
        $hash = (string) ($user['passwordStrong'] ?? '');
        if ($hash === '' || $password === '') {
            return false;
        }
        if (password_verify($password, $hash)) {
            return true;
        }
        $salt = (string) ($user['passwordStrongSalt'] ?? '');
        if ($salt === '') {
            return false;
        }

        return hash_equals($hash, hash('sha256', $salt.$password));
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
        $brand = $this->branding();
        $title = htmlspecialchars($brand['name'].' login', ENT_QUOTES);
        $name = htmlspecialchars($brand['name'], ENT_QUOTES);
        $home = htmlspecialchars($brand['home'], ENT_QUOTES);
        $logo = $brand['logo'] !== ''
            ? '<img class="logo" src="'.htmlspecialchars($brand['logo'], ENT_QUOTES).'" alt="'.htmlspecialchars($brand['name'], ENT_QUOTES).'">'
            : '<div class="logo-text">'.$name.'</div>';
        header('Content-Type: text/html; charset=utf-8');
        echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>'.$title.'</title><style>
          * { box-sizing: border-box; }
          body { margin: 0; min-height: 100vh; font-family: "Nunito", "Helvetica Neue", Helvetica, Arial, sans-serif; color: #333; background: linear-gradient(to left top, #402568 2%, #935ee1 65%, #a871ec) no-repeat fixed; }
          .wrap { max-width: 26rem; margin: 0 auto; padding: 2rem 1.25rem 3rem; }
          .brand { display: block; margin: 0 0 1.25rem; }
          .logo { display: block; max-width: 16rem; max-height: 6.25rem; height: auto; }
          .logo-text { color: #fff; font-size: 1.35rem; font-weight: 700; letter-spacing: .02em; }
          .card { background: #fff; border-radius: .5rem; box-shadow: 0 10px 25px rgba(64,37,104,.18); padding: 1.5rem 1.6rem 1.75rem; }
          h1 { margin: 0 0 .5rem; font-size: 1.05rem; font-weight: 700; letter-spacing: .04em; text-transform: uppercase; color: #444; }
          .lede { margin: 0 0 1.1rem; font-size: .95rem; color: #555; line-height: 1.45; }
          label { display: block; margin: .85rem 0 .35rem; font-size: .8rem; font-weight: 700; text-transform: uppercase; color: #555; }
          input { width: 100%; padding: .55rem .65rem; font: inherit; font-size: 1rem; color: #333; border: 1px solid #ccc; border-radius: .25rem; background: #fff; }
          input:focus { outline: 2px solid #935ee1; outline-offset: 1px; border-color: #7938c9; }
          button { display: block; width: 100%; margin-top: 1.15rem; padding: .65rem 1rem; font: inherit; font-size: .95rem; font-weight: 700; text-transform: uppercase; letter-spacing: .03em; color: #fff; background: #6244bb; border: 0; border-radius: .25rem; cursor: pointer; }
          button:hover { background: #5138a3; }
          .alert { margin: 0 0 1rem; padding: .7rem .85rem; border-radius: .25rem; font-size: .9rem; }
          .alert.error { background: #fde8e8; border: 1px solid #e53e3e; color: #9b2c2c; }
          a { color: #6244bb; }
          code { font-size: .85em; background: #f3eefc; padding: .1rem .3rem; border-radius: .2rem; }
          ul { margin: 0 0 1rem; padding-left: 1.2rem; }
          .foot { margin: 1.25rem 0 0; text-align: center; font-size: .75rem; color: rgba(255,255,255,.8); }
          .foot a { color: #fff; }
        </style></head><body><div class="wrap"><a class="brand" href="'.$home.'">'.$logo.'</a><main class="card">'.$body.'</main><p class="foot">Sign in with your <a href="'.$home.'">'.$name.'</a> account</p></div></body></html>';
    }

    private function htmlError(string $message): void
    {
        http_response_code(400);
        $this->html('<h1>Cannot continue</h1><div class="alert error">'.htmlspecialchars($message, ENT_QUOTES).'</div>');
    }

    private function branding(): array
    {
        $name = $this->store->getSetting('organisationName') ?? 'Gibbon';
        $absolute = rtrim((string) ($this->store->getSetting('absoluteURL') ?? ''), '/');
        $logo = ltrim((string) ($this->store->getSetting('organisationLogo') ?? ''), '/');
        $logoUrl = '';
        if ($absolute !== '' && $logo !== '') {
            $logoUrl = $absolute.'/'.$logo;
        }

        return [
            'name' => $name,
            'home' => $absolute !== '' ? $absolute : $this->issuerUrl(),
            'logo' => $logoUrl,
        ];
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
