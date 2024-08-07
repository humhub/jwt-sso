<?php

/**
 * @link https://www.humhub.org/
 * @copyright Copyright (c) 2019 HumHub GmbH & Co. KG
 * @license https://www.humhub.com/licences
 */

namespace humhub\modules\sso\jwt;

use humhub\modules\sso\jwt\models\Configuration;
use yii\helpers\Url;
use Yii;

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
}
