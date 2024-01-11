<?php

/**
 * @link https://www.humhub.org/
 * @copyright Copyright (c) 2019 HumHub GmbH & Co. KG
 * @license https://www.humhub.com/licences
 */

namespace humhub\modules\sso\jwt;

use humhub\modules\sso\jwt\authclient\JWT;
use humhub\modules\user\authclient\Collection;
use humhub\modules\sso\jwt\models\Configuration;
use humhub\components\Event;
use Yii;

class Events
{

    /**
     * JWT Handling on login page.
     *
     * @param Event $event The event triggering this method.
     * @return void
     * @throws \yii\base\InvalidConfigException If there are configuration issues.
     * @throws \yii\base\InvalidParamException If parameters are invalid.
     * @throws \yii\web\ServerErrorHttpException If a server error occurs.
     * @since 1.1
     */
    public static function onAuthClientCollectionInit($event)
    {
        try {
            if (!Yii::$app->user->isGuest) {
                return;
            }

            if (isset(Yii::$app->authClientCollection) && Yii::$app->authClientCollection->hasClient('jwt')) {
                $jwtAuth = Yii::$app->authClientCollection->getClient('jwt');

                if ($jwtAuth->checkIPAccess()) {
                    if ($jwtAuth->autoLogin && $event->action->id === 'login' && empty(Yii::$app->request->get('noJwt'))) {
                        if ($event->isValid) {
                            $event->isValid = false;
                            return $jwtAuth->redirectToBroker();
                        }
                    }
                } else {
                    Yii::$app->authClientCollection->removeClient('jwt');
                }
            }
        } catch (\Exception $e) {
            // Log or handle the exception as needed
            Yii::error('Error occurred: ' . $e->getMessage());
        }
    }

    /**
     * @param Event $event
     */
    public static function onCollectionAfterClientsSet($event)
    {
        /** @var Collection $authClientCollection */
        $authClientCollection = $event->sender;

        if (!($authClientCollection instanceof Collection)) {
            return;
        }

        if (!empty(Configuration::getInstance()->enabled)) {
            $authClientCollection->setClient('twitter', [
                'class' => authclient\JWT::class,
                'url' => $config->url,
                'sharedKey' => $config->sharedKey,
                'supportedAlgorithms' => $config->supportedAlgorithms,
                'idAttribute' => $config->idAttribute,
                'leeway' => $config->leeway,
                'allowedIPs' => $config->allowedIPs
            ]);
        }
    }
}
