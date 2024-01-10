<?php
/**
 * @link https://www.humhub.org/
 * @copyright Copyright (c) 2019 HumHub GmbH & Co. KG
 * @license https://www.humhub.com/licences
 */

namespace humhub\modules\sso\jwt;

use humhub\modules\sso\jwt\models\Configuration;
use humhub\modules\user\authclient\Collection;
use humhub\components\Event;
use Yii;
use yii\helpers\Url;

class Module extends \humhub\components\Module
{
    public $resourcesPath = 'resources';

    /**
     * @inheritdoc
     */
    public function getConfigUrl()
    {
        return Url::to(['/jwt-sso/admin/index']);
    }

    private ?Configuration $configuration = null;

    public function getConfiguration(): Configuration
    {
        if ($this->configuration === null) {
            $this->configuration = new Configuration(['settingsManager' => $this->settings]);
            $this->configuration->loadBySettings();
        }
        return $this->configuration;
    }

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

            /** @var Collection $authClientCollection */
            $authClientCollection = $event->sender;

            $config = Configuration::getInstance();

            if (!empty($config->enabled)) {
                $authClientCollection->setClient('jwt', [
                    'class' => authclient\JWT::class,
                    'url' => $config->url,
                    'sharedKey' => $config->sharedKey,
                    'supportedAlgorithms' => $config->supportedAlgorithms,
                    'idAttribute' => $config->idAttribute,
                    'leeway' => $config->leeway,
                    'allowedIPs' => $config->allowedIPs
                ]);
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
}
