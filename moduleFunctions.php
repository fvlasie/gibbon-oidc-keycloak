<?php

use Gibbon\Module\OIDCServer\Issuer\Jwt;
use Gibbon\Module\OIDCServer\Issuer\Store;

function oidcServerStore($connection2): Store
{
    static $store;
    if ($store) {
        return $store;
    }

    return $store = new Store($connection2 instanceof PDO ? $connection2 : $GLOBALS['pdo'] ?? $connection2);
}

function oidcServerEnsureKey(Store $store): array
{
    $key = $store->getActiveKey();
    if ($key) {
        return $key;
    }
    $key = Jwt::generateKey();
    $store->saveKey($key);
    $realm = $store->getRealm('gibbon');
    if ($realm) {
        $realm['activeKeyKid'] = $key['kid'];
        $store->upsertRealm($realm);
    }

    return $key;
}
