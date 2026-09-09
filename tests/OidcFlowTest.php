<?php

declare(strict_types=1);

require_once __DIR__.'/../module/issuer/src/Jwt.php';
require_once __DIR__.'/../module/issuer/src/Store.php';
require_once __DIR__.'/../module/issuer/src/Issuer.php';

use Gibbon\Module\OIDCServer\Issuer\Jwt;
use Gibbon\Module\OIDCServer\Issuer\Store;

function assertTrue($cond, string $msg): void
{
    if (!$cond) {
        throw new RuntimeException('FAIL: '.$msg);
    }
    echo "ok  $msg\n";
}

$tmp = sys_get_temp_dir().'/oidc-test-'.bin2hex(random_bytes(4)).'.sqlite';
$store = Store::sqlite($tmp);
$issuerUrl = 'http://idp.test/realms/gibbon';
$store->seedStandaloneDemo($issuerUrl);

$realm = $store->getRealm('gibbon');
assertTrue($realm !== null, 'realm seeded');

$admin = $store->findUserByUsername('admin');
assertTrue($admin && password_verify('changeme', $admin['passwordStrong']), 'admin password');
assertTrue($admin['status'] === 'Full', 'admin is Full');

$left = $store->findUserByUsername('leftuser');
assertTrue($left['status'] === 'Left', 'left user is Left');

$roles = $store->rolesForUser($admin);
assertTrue($roles[0]['name'] === 'Administrator', 'admin role loaded from gibbonRole');

$key = $store->getActiveKey();
$now = time();
$payload = [
    'iss' => $issuerUrl,
    'sub' => '1',
    'aud' => 'account',
    'exp' => $now + 300,
    'iat' => $now,
    'azp' => 'web',
    'typ' => 'Bearer',
    'preferred_username' => 'admin',
    'realm_access' => ['roles' => ['Administrator']],
    'roles' => ['admin'],
];
$jwt = Jwt::sign($payload, $key['privatePem'], $key['kid']);
$verified = Jwt::verify($jwt, $key['publicJwk']);
assertTrue($verified['sub'] === '1', 'JWT verify sub');
assertTrue($verified['azp'] === 'web', 'Keycloak-ish azp');
assertTrue($verified['realm_access']['roles'][0] === 'Administrator', 'realm_access');

$verifier = 'pkce-verifier-value-0123456789';
$challenge = Jwt::b64url(hash('sha256', $verifier, true));
assertTrue(hash_equals($challenge, Jwt::b64url(hash('sha256', $verifier, true))), 'PKCE S256');

$store->saveAuthCode([
    'codeHash' => hash('sha256', 'the-code'),
    'gibbonPersonID' => 1,
    'clientId' => 'web',
    'redirectUri' => $issuerUrl.'/test-rp.html',
    'scope' => 'openid profile email roles',
    'nonce' => 'n',
    'codeChallenge' => $challenge,
    'codeChallengeMethod' => 'S256',
    'sessionId' => 'sid1',
    'expires' => time() + 60,
]);
$taken = $store->takeAuthCode(hash('sha256', 'the-code'));
assertTrue($taken && $taken['clientId'] === 'web', 'auth code single use');
assertTrue($store->takeAuthCode(hash('sha256', 'the-code')) === null, 'auth code gone');

$jwks = $store->listJwks();
assertTrue(($jwks[0]['kid'] ?? '') === $key['kid'], 'JWKS kid');

unlink($tmp);
echo "All tests passed.\n";
