<?php

$name = 'OIDC Server';
$description = 'Keycloak-shaped OpenID Connect issuer using Gibbon accounts, roles, and profile data.';
$entryURL = 'realm_manage.php';
$type = 'Additional';
$category = 'Admin';
$version = '1.0.01';
$author = 'Gibbon OIDC Server';
$url = 'https://gibbonedu.org';

$moduleTables = [];
$schemaPath = __DIR__.'/issuer/schema.mysql.sql';
if (is_file($schemaPath)) {
    $schema = preg_replace('/^--.*$/m', '', (string) file_get_contents($schemaPath)) ?? '';
    foreach (preg_split('/;\s*/', $schema) as $sql) {
        $sql = trim($sql);
        if ($sql === '') {
            continue;
        }
        $moduleTables[] = preg_replace('/^CREATE TABLE IF NOT EXISTS/i', 'CREATE TABLE', $sql);
    }
}
$moduleTables[] = "INSERT INTO oidcRealm (name, issuerUrl, accessTtl, idTtl, refreshTtl) VALUES ('gibbon', CONCAT(TRIM(TRAILING '/' FROM COALESCE((SELECT value FROM gibbonSetting WHERE scope='System' AND name='absoluteURL' LIMIT 1), '')), '/realms/gibbon'), 300, 300, 2592000)";

$gibbonSetting = [];

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
    'description'               => 'Register Keycloak-compatible OIDC clients and redirect URIs.',
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
    'description'               => 'Map Gibbon roles to Keycloak realm_access, roles, and resource_access claims.',
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
__($guid ?? '', 'Register Keycloak-compatible OIDC clients and redirect URIs.');
__($guid ?? '', 'Map Gibbon roles to Keycloak realm_access, roles, and resource_access claims.');
