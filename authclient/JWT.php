<?php

/**
 * @link https://www.humhub.org/
 * @copyright Copyright (c) 2019 HumHub GmbH & Co. KG
 * @license https://www.humhub.com/licences
 */

namespace humhub\modules\sso\jwt\authclient;

use Firebase\JWT\JWT as FirebaseJWT;
use Firebase\JWT\Key as FirebaseJWTKey;
use humhub\modules\user\authclient\interfaces\CustomAuth;
use Yii;
use yii\authclient\BaseClient;
use yii\web\Response;

/**
 * JWT AuthClient — authenticates a HumHub session from a signed JWT presented
 * by an external broker.
 */
class JWT extends BaseClient implements CustomAuth
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
     * @var int maximum allowed lifetime of a token in seconds. If greater than 0, tokens without `exp` claim or with
     * an `exp` further in the future than this value (plus `leeway`) are rejected. Default `0`: not checked.
     * @since 1.2.2
     */
    public $maxTokenAge = 0;

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
     * Backward compatibility for the `supportedAlgorithms` config key used by versions before 1.1.4.
     * Only the first entry is used, since tokens are now verified against a single algorithm.
     *
     * @param string|string[] $algorithms
     * @deprecated since 1.1.4, use `supportedAlgorithm` instead
     */
    public function setSupportedAlgorithms($algorithms)
    {
        $algorithms = (array) $algorithms;
        if (!empty($algorithms)) {
            $this->supportedAlgorithm = (string) reset($algorithms);
        }
    }

    /**
     * @return string[]
     * @deprecated since 1.1.4, use `supportedAlgorithm` instead
     */
    public function getSupportedAlgorithms()
    {
        return [$this->supportedAlgorithm];
    }

    /**
     * @inheritdoc
     *
     * Vanilla `yii\authclient\BaseClient` declares this method abstract;
     * the pre-1.19 `humhub\modules\user\authclient\BaseClient` returned `[]`
     * by default. Preserve that default — actual attributes are populated
     * by {@see handleAuthRequest()} via {@see setUserAttributes()}.
     */
    protected function initUserAttributes()
    {
        return [];
    }

    /**
     * @inheritdoc
     *
     * Migrated from the pre-1.19 `authAction($authAction)` (StandaloneAuthClient).
     * Returning a `Response` short-circuits the flow (redirect to broker / login);
     * returning `null` signals success — core's AuthAction then calls
     * authSuccess() with the populated user attributes automatically.
     */
    public function handleAuthRequest(): ?Response
    {
        // The IP restriction must also apply to already logged-in users, see Module::onAuthClientCollectionInit()
        if (!$this->checkIPAccess()) {
            Yii::$app->session->setFlash('error', Yii::t('JwtSsoModule.jwt', 'JWT login is not allowed from your IP address.'));
            return Yii::$app->getResponse()->redirect(['/user/auth/login']);
        }

        $token = Yii::$app->request->get('jwt');

        if ($token == '') {
            return $this->redirectToBroker();
        }

        try {
            FirebaseJWT::$leeway = $this->leeway;
            $decodedJWT = FirebaseJWT::decode($token, new FirebaseJWTKey($this->sharedKey, $this->supportedAlgorithm));

            if ($this->maxTokenAge > 0) {
                if (!isset($decodedJWT->exp)) {
                    throw new \UnexpectedValueException('Token has no expiration time');
                }
                if ($decodedJWT->exp > time() + $this->maxTokenAge + $this->leeway) {
                    throw new \UnexpectedValueException('Token expiration time is too far in the future');
                }
            }
        } catch (\Exception $ex) {
            Yii::$app->session->setFlash('error', Yii::t('JwtSsoModule.jwt', $ex->getMessage()));
            return Yii::$app->getResponse()->redirect(['/user/auth/login']);
        }

        // Log out the current user only after the token has been verified, otherwise any link could end a session
        if (!Yii::$app->user->isGuest) {
            Yii::$app->user->logout();
        }

        $this->setUserAttributes((array)$decodedJWT);

        return null;
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

    public function redirectToBroker(): Response
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

    public function checkIPAccess()
    {
        if (empty($this->allowedIPs)) {
            return true;
        }

        $ip = Yii::$app->getRequest()->getUserIP();
        foreach ($this->allowedIPs as $filter) {
            if ($filter === '*' || $filter === $ip || (($pos = strpos((string) $filter, '*')) !== false && !strncmp((string) $ip, (string) $filter, $pos))) {
                return true;
            }
        }
        return false;
    }
}
