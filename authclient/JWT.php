<?php

/**
 * @link https://www.humhub.org/
 * @copyright Copyright (c) 2019 HumHub GmbH & Co. KG
 * @license https://www.humhub.com/licences
 */

namespace humhub\modules\sso\jwt\authclient;

use humhub\modules\user\authclient\BaseClient;
use humhub\modules\user\services\AuthClientUserService;
use Yii;
use humhub\modules\user\authclient\interfaces\StandaloneAuthClient;
use humhub\modules\user\models\User;
use Firebase\JWT\JWT as FirebaseJWT;
use Firebase\JWT\Key as FirebaseJWTKey;

/**
 * JWT Authclient
 */
class JWT extends BaseClient implements StandaloneAuthClient
{
    /**
     * @var string url of the JWT provider
     */
    public $url = '';

    /**
     * @var string shared key
     */
    public $sharedKey = '';

    /**
     * @var string jwt verification algorithm. Supported algorithms are 'HS256', 'HS384', 'HS512' and 'RS256'
     */
    public $supportedAlgorithm = 'HS256';

    /**
     * @var string attribute to match user tables with (email, username, id, guid)
     */
    public $idAttribute = 'email';

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
     * @var bool enable automatic login of 'allowed ips'.
     */
    public $autoLogin = false;

    /**
     * @inheritdoc
     */
    public function init()
    {
        parent::init();
        Yii::setAlias('@Firebase/JWT', '@jwt-sso/vendors/php-jwt/src');
    }

    /**
     * @inheritdoc
     */
    public function authAction($authAction)
    {
        $token = Yii::$app->request->get('jwt');

        if (!Yii::$app->user->isGuest) {
            Yii::$app->user->logout();
        }

        if ($token == '') {
            return $this->redirectToBroker();
        }

        try {
            FirebaseJWT::$leeway = $this->leeway;
            $decodedJWT = FirebaseJWT::decode($token, new FirebaseJWTKey($this->sharedKey, $this->supportedAlgorithm));
        } catch (\Exception $ex) {
            Yii::$app->session->setFlash('error', Yii::t('JwtSsoModule.jwt', $ex->getMessage()));
            return Yii::$app->getResponse()->redirect(['/user/auth/login']);
        }

        $this->setUserAttributes((array)$decodedJWT);
        $this->autoStoreAuthClient();


        return $authAction->authSuccess($this);
    }

    /**
     * @inheritdoc
     */
    public function setUserAttributes($userAttributes)
    {
        // Remove JWT Attributes
        unset($userAttributes['iss']);
        unset($userAttributes['jti']);
        unset($userAttributes['iat']);

        if (!isset($userAttributes['id'])) {
            if ($this->idAttribute == 'email' && isset($userAttributes['email'])) {
                $userAttributes['id'] = $userAttributes['email'];
            } elseif ($this->idAttribute == 'guid' && isset($userAttributes['guid'])) {
                $userAttributes['guid'] = $userAttributes['guid'];
            } elseif ($this->idAttribute == 'username' && isset($userAttributes['username'])) {
                $userAttributes['username'] = $userAttributes['username'];
            }
        }

        return parent::setUserAttributes($userAttributes);
    }

    public function redirectToBroker()
    {
        return Yii::$app->getResponse()->redirect($this->url);
    }

    /**
     * @inheritdoc
     */
    protected function defaultViewOptions()
    {
        return [
            'cssIcon' => 'fa fa-fast-forward',
            'buttonBackgroundColor' => '#4078C0',
        ];
    }

    /**
     * @inheritdoc
     */
    protected function defaultName()
    {
        return 'jwt';
    }

    /**
     * @inheritdoc
     */
    protected function defaultTitle()
    {
        return 'JWT SSO';
    }

    /**
     * Automatically stores this auth client to a found user.
     * So the user doesn't needs to login and manually set this authclient
     */
    protected function autoStoreAuthClient()
    {
        $user = $this->getUserByAttributes();
        if ($user !== null) {
            (new AuthClientUserService($user))->add($this);
        }
    }

    /**
     * @return User|null
     */
    protected function getUserByAttributes()
    {
        $attributes = $this->getUserAttributes();
        if (isset($attributes['email'])) {
            return User::findOne(['email' => $attributes['email']]);
        }

        return null;
    }

    public function checkIPAccess()
    {
        if (empty($this->allowedIPs)) {
            return true;
        }

        $ip = Yii::$app->getRequest()->getUserIP();
        foreach ($this->allowedIPs as $filter) {
            if ($filter === '*' || $filter === $ip || (($pos = strpos($filter, '*')) !== false && !strncmp($ip, $filter, $pos))) {
                return true;
            }
        }
        return false;
    }

}
