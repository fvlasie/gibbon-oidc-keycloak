<?php

use Gibbon\Http\Url;

if (!function_exists('isActionAccessible') || isActionAccessible($guid, $connection2, '/modules/OIDC Server/realm_manage.php') == false) {
    $page->addError(__('You do not have access to this action.'));
    return;
}

header('Location: '.Url::fromModuleRoute('OIDC Server', 'realm_manage'));
