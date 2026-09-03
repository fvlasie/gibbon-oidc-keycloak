<?php

require_once __DIR__.'/issuer/bootstrap.php';
require_once __DIR__.'/moduleFunctions.php';

use Gibbon\Forms\Form;

if (isActionAccessible($guid, $connection2, '/modules/OIDC Server/claims_manage.php') == false) {
    $page->addError(__('You do not have access to this action.'));
    return;
}

$store = new \Gibbon\Module\OIDCServer\Issuer\Store($connection2);

$roles = $connection2->query('SELECT gibbonRoleID, name, category FROM gibbonRole ORDER BY name')->fetchAll();

if (isset($_POST['maps']) && is_array($_POST['maps'])) {
    $maps = [];
    foreach ($_POST['maps'] as $map) {
        if (empty($map['gibbonRoleID']) || empty($map['realmRole'])) {
            continue;
        }
        $maps[] = [
            'gibbonRoleID' => (int) $map['gibbonRoleID'],
            'realmRole' => trim((string) $map['realmRole']),
            'opencloudRole' => trim((string) ($map['opencloudRole'] ?? '')) ?: null,
            'clientId' => trim((string) ($map['clientId'] ?? '')) ?: null,
            'clientRole' => trim((string) ($map['clientRole'] ?? '')) ?: null,
        ];
    }
    $store->replaceClaimMaps($maps);
    $page->addSuccess(__('Your request was completed successfully.'));
}

$existing = [];
foreach ($store->listClaimMaps() as $map) {
    $existing[(int) $map['gibbonRoleID']] = $map;
}

$page->breadcrumbs->add(__('OIDC Role Claims'));
echo '<p>'.__('Every Gibbon role name is always added to realm_access.roles. Use this table to add OpenCloud roles (opencloudAdmin, opencloudUser, opencloudGuest, opencloudSpaceAdmin) and optional per-client resource_access roles.').'</p>';

if ($roles === []) {
    echo '<p><em>'.__('No Gibbon roles were found.').'</em></p>';
    return;
}

$form = Form::create('claims', $session->get('absoluteURL').'/index.php?q=/modules/OIDC Server/claims_manage.php');
$form->addHiddenValue('address', $_GET['q'] ?? '');

foreach ($roles as $i => $role) {
    $map = $existing[(int) $role['gibbonRoleID']] ?? [];
    $form->addRow()->addHeading($role['name'].' ('.$role['category'].')');
    $form->addHiddenValue("maps[$i][gibbonRoleID]", $role['gibbonRoleID']);
    $form->addRow()->addLabel("maps[$i][realmRole]", __('Realm role claim'));
    $form->addRow()->addTextField("maps[$i][realmRole]")->setValue($map['realmRole'] ?? $role['name']);
    $form->addRow()->addLabel("maps[$i][opencloudRole]", __('OpenCloud roles claim'));
    $form->addRow()->addTextField("maps[$i][opencloudRole]")->setValue($map['opencloudRole'] ?? '');
    $form->addRow()->addLabel("maps[$i][clientId]", __('Resource client ID'));
    $form->addRow()->addTextField("maps[$i][clientId]")->setValue($map['clientId'] ?? '');
    $form->addRow()->addLabel("maps[$i][clientRole]", __('Resource role'));
    $form->addRow()->addTextField("maps[$i][clientRole]")->setValue($map['clientRole'] ?? '');
}

$form->addRow()->addSubmit();
echo $form->getOutput();
