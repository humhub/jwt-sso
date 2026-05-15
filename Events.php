<?php

/**
 * @link https://www.humhub.org/
 * @copyright Copyright (c) 2019 HumHub GmbH & Co. KG
 * @license https://www.humhub.com/licences
 */

namespace humhub\modules\sso\jwt;

use humhub\libs\ParameterEvent;
use humhub\modules\sso\jwt\source\JwtUserSource;
use Yii;

class Events
{
    /**
     * Registers a JwtUserSource when the module's `provideUserSource` opt-in
     * is enabled. Without it new JWT users fall back to LocalUserSource (the
     * pre-1.19 default once `auth_mode` was dropped).
     *
     * @param ParameterEvent $event
     */
    public static function onUserSourceCollectionSet($event)
    {
        /** @var Module $module */
        $module = Yii::$app->getModule('jwt-sso');

        if (!$module->provideUserSource) {
            return;
        }

        $event->parameters['userSources'][JwtUserSource::SOURCE_ID] = [
            'class' => JwtUserSource::class,
        ];
    }
}
