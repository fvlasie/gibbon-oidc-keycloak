<?php

require_once __DIR__.'/issuer/bootstrap.php';
require_once __DIR__.'/moduleFunctions.php';

use Gibbon\Forms\Form;

if (isActionAccessible($guid, $connection2, '/modules/OIDC Server/clients_manage.php') == false) {
    $page->addError(__('You do not have access to this action.'));
    return;
}

$store = new \Gibbon\Module\OIDCServer\Issuer\Store($connection2);

if (!empty($_POST['clientId'])) {
    $store->upsertClient([
        'clientId' => trim((string) $_POST['clientId']),
        'public' => !empty($_POST['public']) ? 'Y' : 'N',
        'pkceRequired' => !empty($_POST['pkceRequired']) ? 'Y' : 'N',
        'redirectUris' => (string) $_POST['redirectUris'],
        'postLogoutUris' => (string) ($_POST['postLogoutUris'] ?? ''),
        'allowedScopes' => (string) ($_POST['allowedScopes'] ?? 'openid profile email offline_access roles'),
        'allowedOrigins' => (string) ($_POST['allowedOrigins'] ?? '*'),
        'clientSecretHash' => !empty($_POST['clientSecret']) ? password_hash((string) $_POST['clientSecret'], PASSWORD_DEFAULT) : null,
    ]);
    $page->addSuccess(__('Your request was completed successfully.'));
}

$page->breadcrumbs->add(__('OIDC Clients'));
echo '<p>'.__('Register each Keycloak-compatible application as a client. Use the same client ID the app expects, and list every redirect URI exactly, one per line. Public clients should use PKCE. Confidential clients need a secret (client_secret_post or HTTP Basic).').'</p>';

$clients = $store->listClients();
if ($clients === []) {
    echo '<p><em>'.__('There are no clients yet. Add one below.').'</em></p>';
} else {
    echo '<table class="mini colorOddEven w-full"><thead><tr><th>'.__('Client ID').'</th><th>'.__('Public').'</th><th>'.__('PKCE').'</th><th>'.__('Redirect URIs').'</th></tr></thead><tbody>';
    foreach ($clients as $client) {
        echo '<tr><td>'.htmlspecialchars($client['clientId'], ENT_QUOTES).'</td><td>'.$client['public'].'</td><td>'.$client['pkceRequired'].'</td><td><pre>'.htmlspecialchars($client['redirectUris'], ENT_QUOTES).'</pre></td></tr>';
    }
    echo '</tbody></table>';
}

$form = Form::create('client', $session->get('absoluteURL').'/index.php?q=/modules/OIDC Server/clients_manage.php');
$form->addHiddenValue('address', $_GET['q'] ?? '');
$form->addRow()->addLabel('clientId', __('Client ID'))->description(__('Must match the application OIDC client_id (create a new row or overwrite an existing ID).'));
$form->addRow()->addTextField('clientId')->required();
$form->addRow()->addCheckbox('public')->description(__('Public client (no secret; typical for SPAs and native apps with PKCE)'))->checked(true);
$form->addRow()->addCheckbox('pkceRequired')->description(__('Require PKCE'))->checked(true);
$form->addRow()->addLabel('redirectUris', __('Redirect URIs'))->description(__('One URI per line; must match exactly.'));
$form->addRow()->addTextArea('redirectUris')->required()->setRows(5);
$form->addRow()->addLabel('postLogoutUris', __('Post-logout redirect URIs'));
$form->addRow()->addTextArea('postLogoutUris')->setRows(3);
$form->addRow()->addLabel('allowedScopes', __('Allowed scopes'));
$form->addRow()->addTextField('allowedScopes')->setValue('openid profile email offline_access roles');
$form->addRow()->addLabel('allowedOrigins', __('Allowed origins'))->description(__('CORS / allowed-origins claim. Use * or one origin per line.'));
$form->addRow()->addTextArea('allowedOrigins')->setValue('*')->setRows(2);
$form->addRow()->addLabel('clientSecret', __('Client secret'))->description(__('Only for confidential clients. Leave blank to keep the existing secret.'));
$form->addRow()->addPassword('clientSecret');
$form->addRow()->addSubmit();
echo $form->getOutput();
