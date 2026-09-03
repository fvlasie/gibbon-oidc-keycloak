<?php

namespace Gibbon\Module\OIDCServer\Issuer;

require_once __DIR__.'/src/Jwt.php';
require_once __DIR__.'/src/Store.php';
require_once __DIR__.'/src/Issuer.php';

function boot(): Issuer
{
    $publicOrigin = rtrim(getenv('OIDC_PUBLIC_ORIGIN') ?: detectOrigin(), '/');
    $basePath = rtrim(getenv('OIDC_BASE_PATH') ?: '', '/');
    $realm = getenv('OIDC_REALM') ?: 'gibbon';

    $gibbonRoot = dirname(__DIR__, 3);
    $configFile = $gibbonRoot.'/config.php';

    if (is_file($configFile) && getenv('OIDC_STANDALONE') !== '1') {
        $databaseServer = $databaseUsername = $databasePassword = $databaseName = $databasePort = null;
        require $configFile;
        $port = !empty($databasePort) ? ';port='.$databasePort : '';
        $store = Store::mysql(
            'mysql:host='.$databaseServer.';dbname='.$databaseName.$port.';charset=utf8mb4',
            $databaseUsername,
            $databasePassword
        );
    } else {
        $sqlite = getenv('OIDC_SQLITE') ?: dirname(__DIR__, 2).'/var/oidc.sqlite';
        $store = Store::sqlite($sqlite);
        $store->seedStandaloneDemo($publicOrigin.$basePath.'/realms/'.$realm);
    }

    return new Issuer($store, $realm, $publicOrigin, $basePath);
}

function detectOrigin(): string
{
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['SERVER_PORT'] ?? '') == 443)
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
    $scheme = $https ? 'https' : 'http';
    $host = $_SERVER['HTTP_X_FORWARDED_HOST'] ?? $_SERVER['HTTP_HOST'] ?? '127.0.0.1:43180';

    return $scheme.'://'.$host;
}
