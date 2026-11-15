<?php

/**
 * @link https://www.humhub.org/
 * @copyright Copyright (c) 2019 HumHub GmbH & Co. KG
 * @license https://www.humhub.com/licences
 */

namespace humhub\modules\sso\jwt\authclient;

use Firebase\JWT\JWT as FirebaseJWT;
use Firebase\JWT\Key as FirebaseJWTKey;
use humhub\libs\ParameterEvent;
use humhub\modules\user\authclient\interfaces\CustomAuth;
use humhub\modules\user\models\Group;
use Yii;
use yii\authclient\BaseClient;
use yii\base\Application;
use yii\base\Event;
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
     * @since 1.3.0
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
     * @var int[] IDs of the groups a token may assign to a new user through its `group_id` claim.
     * The user is only added to the group named in the claim, and only when the account is created.
     * Listed groups don't need to be shown at registration. A `group_id` of an unlisted group is only accepted
     * by the registration if it is a registration group (behaviour before this option).
     * @since 1.3.0
     */
    public $assignableGroupIds = [];

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

        // Only a token verified in this request may assign a group, see onGetRegistrationGroups()
        self::detachRegistrationGroupsHandler();
        $group = $this->resolveAssignableGroup($this->getUserAttributes()['group_id'] ?? null);
        if ($group !== null) {
            Event::on(Group::class, Group::EVENT_GET_REGISTRATION_GROUPS, [self::class, 'onGetRegistrationGroups'], $group);
            // Class-level handlers are static state: make sure it doesn't outlive this request (long-running workers)
            Yii::$app->off(Application::EVENT_AFTER_REQUEST, [self::class, 'detachRegistrationGroupsHandler']);
            Yii::$app->on(Application::EVENT_AFTER_REQUEST, [self::class, 'detachRegistrationGroupsHandler']);
        }

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

    /**
     * Returns the group of the `group_id` claim if it is listed in {@see $assignableGroupIds}, exists and is not an
     * administrator group, otherwise `null`. A claim of an unlisted group is left to the registration, which only
     * accepts registration groups.
     *
     * @param mixed $groupId value of the `group_id` claim
     * @since 1.3.0
     */
    protected function resolveAssignableGroup($groupId): ?Group
    {
        if ($groupId === null) {
            return null;
        }

        if (!is_int($groupId) && !(is_string($groupId) && ctype_digit($groupId))) {
            Yii::warning('JWT: invalid group_id claim, a new user will not be added to any group.', 'jwt-sso');
            return null;
        }

        $groupId = (int) $groupId;

        if (!in_array($groupId, array_map('intval', (array) $this->assignableGroupIds), true)) {
            // The registration silently assigns no group at all (not even the default group) for such a claim
            $registrationGroupIds = array_map(fn(Group $group) => (int) $group->id, Group::getRegistrationGroups());
            if (!in_array($groupId, $registrationGroupIds, true)) {
                Yii::warning('JWT: group ' . $groupId . ' of the group_id claim is neither in assignableGroupIds nor a registration group, a new user will not be added to any group.', 'jwt-sso');
            }
            return null;
        }

        $group = Group::findOne(['id' => $groupId]);
        if ($group === null) {
            Yii::warning('JWT: group ' . $groupId . ' of assignableGroupIds does not exist.', 'jwt-sso');
            return null;
        }

        if ($group->is_admin_group) {
            Yii::warning('JWT: group ' . $groupId . ' of assignableGroupIds is an administrator group and cannot be assigned.', 'jwt-sso');
            return null;
        }

        return $group;
    }

    /**
     * Makes the group of the `group_id` claim a valid registration group, so the registration of the new
     * user accepts it. Attached by {@see handleAuthRequest()} only after a token has been verified and
     * its `group_id` checked against {@see $assignableGroupIds}, so the group never becomes selectable
     * in the registration form.
     *
     * @param ParameterEvent $event `data` holds the {@see Group}
     * @since 1.3.0
     */
    public static function onGetRegistrationGroups($event)
    {
        foreach ($event->parameters['groups'] as $group) {
            if ((int) $group->id === (int) $event->data->id) {
                return;
            }
        }

        $event->parameters['groups'][] = $event->data;
    }

    /**
     * Detaches {@see onGetRegistrationGroups()}, so the group of a token never stays a registration group
     * after the request in which the token was verified.
     *
     * @since 1.3.0
     */
    public static function detachRegistrationGroupsHandler(): void
    {
        Event::off(Group::class, Group::EVENT_GET_REGISTRATION_GROUPS, [self::class, 'onGetRegistrationGroups']);
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
