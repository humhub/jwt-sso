<?php

/**
 * @link https://www.humhub.org/
 * @copyright Copyright (c) 2019 HumHub GmbH & Co. KG
 * @license https://www.humhub.com/licences
 */

namespace humhub\modules\sso\jwt;

use humhub\components\Event;
use Yii;
use yii\helpers\Url;

class Module extends \humhub\components\Module
{
    public $resourcesPath = 'resources';

    /**
     * Opt-in: register a dedicated `JwtUserSource` that owns users provisioned
     * via JWT. Enables attribute sync (default: email + username) and source
     * isolation (users get `user_source = 'jwt'`) — the post-1.19 replacement
     * for the legacy `JWTPrimary` marker.
     *
     * Default is `false` to preserve the existing behaviour on upgrade: JWT
     * users keep landing in `LocalUserSource` and admins can flip this on
     * once they're ready for the new model.
     *
     * Set via `config/common.php`:
     * ```php
     * 'modules' => [
     *     'jwt-sso' => ['provideUserSource' => true],
     * ],
     * ```
     *
     * @since 1.2.0
     */
    public bool $provideUserSource = false;

    /**
     * JWT Handling on login page
     *
     * @param Event $event
     * @return void
     * @throws \yii\base\InvalidConfigException
     * @since 1.1
     */
    public static function onAuthClientCollectionInit($event)
    {
        if (!Yii::$app->user->isGuest) {
            return;
        }

        if (Yii::$app->authClientCollection->hasClient('jwt')) {
            $jwtAuth = Yii::$app->authClientCollection->getClient('jwt');

            if ($jwtAuth->checkIPAccess()) {
                if ($jwtAuth->autoLogin && $event->action->id == 'login' && empty(Yii::$app->request->get('noJwt'))) {
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
