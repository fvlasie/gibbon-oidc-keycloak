<?php

$name = 'OIDC Server';
$description = 'Keycloak-shaped OpenID Connect issuer using Gibbon accounts, roles, and profile data.';
$entryURL = 'realm_manage.php';
$type = 'Additional';
$category = 'Admin';
$version = '1.0.00';
$author = 'Gibbon OIDC Server';
$url = 'https://gibbonedu.org';

$moduleTables = [];

$gibbonSetting = [];

// Seed realm + OpenCloud public clients after tables exist (install.php runs extra SQL from $sqlExtra if present)
$sqlExtra = [];

$absoluteURL = $absoluteURL ?? '';

$sqlExtra[] = "INSERT INTO oidcRealm (name, issuerUrl, accessTtl, idTtl, refreshTtl) VALUES ('gibbon', CONCAT(TRIM(TRAILING '/' FROM COALESCE((SELECT value FROM gibbonSetting WHERE scope='System' AND name='absoluteURL' LIMIT 1), '')), '/'), '/realms/gibbon'), 300, 300, 2592000)";

$openCloudRedirects = "oc://android\noc://ios\nhttp://127.0.0.1:9200/oidc-callback.html";
foreach (['web', 'OpenCloudDesktop', 'OpenCloudAndroid', 'OpenCloudIOS'] as $clientId) {
    $sqlExtra[] = "INSERT INTO oidcClient (clientId, public, redirectUris, allowedScopes, pkceRequired, allowedOrigins) VALUES ('".$clientId."', 'Y', '".$openCloudRedirects."', 'openid profile email offline_access roles', 'Y', '*')";
}

$actionRows[] = [
    'name'                      => 'Manage Realm',
    'precedence'                => '0',
    'category'                  => 'OIDC',
    'description'               => 'Configure the issuer URL, token lifetimes, and signing keys.',
    'URLList'                   => 'realm_manage.php',
    'entryURL'                  => 'realm_manage.php',
    'defaultPermissionAdmin'    => 'Y',
    'defaultPermissionTeacher'  => 'N',
    'defaultPermissionStudent'  => 'N',
    'defaultPermissionParent'   => 'N',
    'defaultPermissionSupport'  => 'N',
    'categoryPermissionStaff'   => 'Y',
    'categoryPermissionStudent' => 'N',
    'categoryPermissionParent'  => 'N',
    'categoryPermissionOther'   => 'N',
];

$actionRows[] = [
    'name'                      => 'Manage Clients',
    'precedence'                => '0',
    'category'                  => 'OIDC',
    'description'               => 'Register OIDC / OpenCloud clients and redirect URIs.',
    'URLList'                   => 'clients_manage.php',
    'entryURL'                  => 'clients_manage.php',
    'defaultPermissionAdmin'    => 'Y',
    'defaultPermissionTeacher'  => 'N',
    'defaultPermissionStudent'  => 'N',
    'defaultPermissionParent'   => 'N',
    'defaultPermissionSupport'  => 'N',
    'categoryPermissionStaff'   => 'Y',
    'categoryPermissionStudent' => 'N',
    'categoryPermissionParent'  => 'N',
    'categoryPermissionOther'   => 'N',
];

$actionRows[] = [
    'name'                      => 'Manage Claims',
    'precedence'                => '0',
    'category'                  => 'OIDC',
    'description'               => 'Map Gibbon roles to Keycloak realm roles and OpenCloud role claims.',
    'URLList'                   => 'claims_manage.php',
    'entryURL'                  => 'claims_manage.php',
    'defaultPermissionAdmin'    => 'Y',
    'defaultPermissionTeacher'  => 'N',
    'defaultPermissionStudent'  => 'N',
    'defaultPermissionParent'   => 'N',
    'defaultPermissionSupport'  => 'N',
    'categoryPermissionStaff'   => 'Y',
    'categoryPermissionStudent' => 'N',
    'categoryPermissionParent'  => 'N',
    'categoryPermissionOther'   => 'N',
];

__($guid ?? '', 'Configure the issuer URL, token lifetimes, and signing keys.');
__($guid ?? '', 'Register OIDC / OpenCloud clients and redirect URIs.');
__($guid ?? '', 'Map Gibbon roles to Keycloak realm roles and OpenCloud role claims.');
