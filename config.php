<?php

/** @noinspection MissedFieldInspection */

use humhub\modules\user\controllers\AuthController;
use humhub\modules\user\authclient\Collection;

return [
    'id' => 'jwt-sso',
    'class' => 'humhub\modules\sso\jwt\Module',
    'namespace' => 'humhub\modules\sso\jwt',
    'events' => [
        [Collection::class, Collection::EVENT_AFTER_CLIENTS_SET, ['humhub\modules\sso\jwt\Events', 'onAuthClientCollectionInit']],
        [AuthController::class, AuthController::EVENT_BEFORE_ACTION, ['humhub\modules\sso\jwt\Events', 'onAuthClientCollectionInit']],
    ]
];
?>
