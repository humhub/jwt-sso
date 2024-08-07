<?php

namespace humhub\modules\sso\jwt\models;

use humhub\components\SettingsManager;
use Yii;
use yii\helpers\ArrayHelper;
use yii\base\Model;

class Configuration extends Model
{
    const HS256 = 'HS256';
    const HS384 = 'HS384';
    const HS512 = 'HS512';
    const RS256 = 'RS256';

    public ?SettingsManager $settingsManager = null;

    /**
     * @var boolean enabled state of the JWT provider
     */
    public $enabled;

    /**
     * @var string url of the JWT provider
     */
    public $url = '';

    /**
     * @var string shared key
     */
    public $sharedKey = '';

    /**
     * @var array a list of supported jwt verification algorithms Supported algorithms are 'HS256', 'HS384', 'HS512' and 'RS256'
     */
    public $supportedAlgorithms = [];

    /**
     * @var string attribute to match user tables with (email, username, id, guid)
     */
    public $idAttribute = 'email';

    /**
     * @var boolean enable automatic login of 'allowed ips'.
     */
    public $autoLogin;

    /**
     * @var int token time leeway
     */
    public $leeway = 60;

    /**
     * @var array the list of IPs that are allowed to use JWT.
     * Each array element represents a single IP filter which can be either an IP address
     * or an address with wildcard (e.g. 192.168.0.*) to represent a network segment.
     */
    public $allowedIPs = [];

    /**
     * @inheritdoc
     */
    public function rules()
    {
        return [
            [['url', 'sharedKey', 'supportedAlgorithms', 'allowedIPs', 'leeway'], 'safe'],
            [['enabled', 'autoLogin'], 'boolean'],
            [['idAttribute'], 'string']
        ];
    }

    public function afterFind()
    {
        $this->updateState();
        parent::afterFind();
    }

    public static function getAlgorithm($supportedAlgorithms) : array
    {
        return self::getAlgorithms()[$supportedAlgorithms];
    }

    /**
     * @return requests for dark/light modes
     */
    public static function getAlgorithms($selectable = true) : array
    {
        $supportedAlgorithms = [
            self::HS256 => 'HS256',
            self::HS384 => 'HS384',
            self::HS512 => 'HS512',
            self::RS256 => 'RS256'
        ];

        if ($selectable) {
            return $supportedAlgorithms;
        }

        return $supportedAlgorithms;
    }

    /**
     * @inheritdoc
     */
    public function attributeLabels()
    {
        return [
            'url' => Yii::t('JwtSsoModule.base', 'Url'),
            'sharedKey' => Yii::t('JwtSsoModule.base', 'Shared Key'),
            'supportedAlgorithms' => Yii::t('JwtSsoModule.base', 'Supported Algorithms'),
            'idAttribute' => Yii::t('JwtSsoModule.base', 'ID Attribute'),
            'leeway' => Yii::t('JwtSsoModule.base', 'Leeway'),
            'allowedIPs' => Yii::t('JwtSsoModule.base', 'Allowed IPs'),
        ];
    }

    public function loadBySettings()
    {
        if ($this->settingsManager !== null) {
            $this->enabled = (bool)$this->settingsManager->get('enabled') ?? true;
            $this->url = (string)($this->settingsManager->get('url') ?? '');
            $this->sharedKey = $this->settingsManager->getSerialized('sharedKey') ?? '';
            $this->supportedAlgorithms = (array)($this->settingsManager->get('supportedAlgorithms') ?? []);
            $this->idAttribute = (string)($this->settingsManager->get('idAttribute') ?? '');
            $this->leeway = $this->settingsManager->get('leeway') ?? 0;
            $this->allowedIPs = (array)($this->settingsManager->get('allowedIPs') ?? []);
            $this->autoLogin = (bool)$this->settingsManager->get('autoLogin') ?? false;
        }
    }

    public function save()
    {
        if (!$this->validate()) {
            return false;
        }

        $this->settingsManager->set('enabled', $this->enabled);
        $this->settingsManager->set('url', $this->url);
        $this->settingsManager->setSerialized('sharedKey', (string)$this->sharedKey);
        $this->settingsManager->set('supportedAlgorithms', (array)$this->supportedAlgorithms);
        $this->settingsManager->set('idAttribute', $this->idAttribute);
        $this->settingsManager->set('leeway', $this->leeway);
        $this->settingsManager->set('allowedIPs', (array)$this->allowedIPs);
        $this->settingsManager->set('autoLogin', $this->autoLogin);

        return true;
    }

    /**
     * Returns a loaded instance of this configuration model
     */
    public static function getInstance()
    {
        $config = new static;
        $config->loadBySettings();

        return $config;
    }

}
