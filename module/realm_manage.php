<?php

require_once __DIR__.'/issuer/bootstrap.php';
require_once __DIR__.'/moduleFunctions.php';

use Gibbon\Forms\Form;
use Gibbon\Module\OIDCServer\Issuer\Jwt;

if (isActionAccessible($guid, $connection2, '/modules/OIDC Server/realm_manage.php') == false) {
    $page->addError(__('You do not have access to this action.'));
    return;
}

$store = new \Gibbon\Module\OIDCServer\Issuer\Store($connection2);
$realm = $store->getRealm('gibbon');
if (!$realm) {
    $absolute = rtrim((string) $session->get('absoluteURL'), '/');
    $store->upsertRealm([
        'name' => 'gibbon',
        'issuerUrl' => $absolute.'/realms/gibbon',
        'accessTtl' => 300,
        'idTtl' => 300,
        'refreshTtl' => 2592000,
        'activeKeyKid' => null,
    ]);
    $realm = $store->getRealm('gibbon');
}

if (!empty($_POST['issuerUrl'])) {
    if (!empty($_POST['rotateKey'])) {
        $key = Jwt::generateKey();
        $store->saveKey($key);
        $realm['activeKeyKid'] = $key['kid'];
    }
    $realm['issuerUrl'] = rtrim((string) $_POST['issuerUrl'], '/');
    $realm['accessTtl'] = max(60, (int) $_POST['accessTtl']);
    $realm['idTtl'] = max(60, (int) $_POST['idTtl']);
    $realm['refreshTtl'] = max(300, (int) $_POST['refreshTtl']);
    $store->upsertRealm($realm);
    oidcServerEnsureKey($store);
    $page->addSuccess(__('Your request was completed successfully.'));
    $realm = $store->getRealm('gibbon');
}

$key = oidcServerEnsureKey($store);

$page->breadcrumbs->add(__('OIDC Realm'));

echo '<p>'.__('This module is the OpenID Connect issuer for this Gibbon site. Point OpenCloud or another Keycloak-shaped client at the discovery URL after you add the web-server rewrite for /realms/.').'</p>';

$discovery = htmlspecialchars($realm['issuerUrl'].'/.well-known/openid-configuration', ENT_QUOTES);
echo '<p><strong>'.__('Discovery URL').':</strong> <code>'.$discovery.'</code></p>';
echo '<p><strong>'.__('Active signing key').':</strong> <code>'.htmlspecialchars((string) $key['kid'], ENT_QUOTES).'</code></p>';

$form = Form::create('realm', $session->get('absoluteURL').'/index.php?q=/modules/OIDC Server/realm_manage.php');
$form->addHiddenValue('address', $_GET['q'] ?? '');
$form->addRow()->addLabel('issuerUrl', __('Issuer URL'))->description(__('Must match OC_OIDC_ISSUER exactly, including https.'));
$form->addRow()->addTextField('issuerUrl')->required()->setValue($realm['issuerUrl']);
$form->addRow()->addLabel('accessTtl', __('Access token lifetime (seconds)'));
$form->addRow()->addNumber('accessTtl')->required()->setValue($realm['accessTtl']);
$form->addRow()->addLabel('idTtl', __('ID token lifetime (seconds)'));
$form->addRow()->addNumber('idTtl')->required()->setValue($realm['idTtl']);
$form->addRow()->addLabel('refreshTtl', __('Refresh token lifetime (seconds)'));
$form->addRow()->addNumber('refreshTtl')->required()->setValue($realm['refreshTtl']);
$row = $form->addRow();
$row->addCheckbox('rotateKey')->description(__('Generate a new RSA signing key (previous keys stay in JWKS until you delete them).'));
$form->addRow()->addSubmit();

echo $form->getOutput();
