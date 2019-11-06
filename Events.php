<?php

/**
 * @link https://www.humhub.org/
 * @copyright Copyright (c) 2019 HumHub GmbH & Co. KG
 * @license https://www.humhub.com/licences
 */

namespace humhub\modules\sso\jwt;


use humhub\modules\sso\jwt\authclient\JWT;
use Yii;

class Events
{
    /**
     * JWT Handling on login page
     *
     * @param \yii\base\ActionEvent $event
     * @return void
     * @since 1.1
     */
    public static function onAuthClientCollectionInit($event)
    {
        if (!Yii::$app->user->isGuest) {
            return;
        }

        if (Yii::$app->authClientCollection->hasClient('jwt')) {
            /** @var JWT $jwtAuth */
            $jwtAuth = Yii::$app->authClientCollection->getClient('jwt');

            if ($jwtAuth->checkIPAccess()) {
                if ($jwtAuth->autoLogin && $event->action->id == 'login') {
                    $event->isValid = false;
                    return $jwtAuth->redirectToBroker();
                }
            } else {
                // Not allowed, remove authClient
                Yii::$app->authClientCollection->removeClient('jwt');
            }
        }
    }
}
