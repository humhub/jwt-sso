<?php

/** @noinspection MissedFieldInspection */

use humhub\modules\sso\jwt\Events;
use humhub\modules\user\controllers\AuthController;
use humhub\modules\user\source\UserSourceCollection;

return [
    'id' => 'jwt-sso',
    'class' => 'humhub\modules\sso\jwt\Module',
    'namespace' => 'humhub\modules\sso\jwt',
    'events' => [
        [AuthController::class, AuthController::EVENT_BEFORE_ACTION, ['humhub\modules\sso\jwt\Module', 'onAuthClientCollectionInit']],
        [UserSourceCollection::class, UserSourceCollection::EVENT_BEFORE_USER_SOURCES_SET, [Events::class, 'onUserSourceCollectionSet']],
    ],
];
