<?php

/**
 * @link https://www.humhub.org/
 * @copyright Copyright (c) 2026 HumHub GmbH & Co. KG
 * @license https://www.humhub.com/licences
 */

namespace humhub\modules\sso\jwt\source;

use humhub\modules\sso\jwt\Module;
use humhub\modules\user\models\forms\Registration;
use humhub\modules\user\models\User;
use humhub\modules\user\source\BaseUserSource;
use humhub\modules\user\source\UserSourceInterface;
use Yii;
use yii\helpers\VarDumper;

/**
 * JwtUserSource owns users provisioned through the JWT auth client.
 *
 * Registered by {@see Events::onUserSourceCollectionSet()} when the module's
 * {@see Module::$provideUserSource} property is enabled. When the source is
 * NOT registered, JWT users fall back into `LocalUserSource` and the
 * pre-1.19 `$syncAttributes` / `ApprovalBypass` behaviour is lost.
 *
 * @since 1.2.0
 */
class JwtUserSource extends BaseUserSource
{
    public const SOURCE_ID = 'jwt';

    /**
     * @var bool Whether JWT logins bypass the admin-approval step. Mirrors
     * the pre-1.19 `ApprovalBypass` marker. When true, installs 'jwt' into
     * {@see $trustedAuthClientIds} so {@see BaseUserSource::requiresApproval()}
     * short-circuits before consulting {@see $approval}.
     */
    public bool $bypassApproval = false;

    public function init()
    {
        parent::init();

        if ($this->id === '') {
            $this->id = self::SOURCE_ID;
        }
        if ($this->allowedAuthClientIds === []) {
            $this->allowedAuthClientIds = [self::SOURCE_ID];
        }
        if ($this->managedAttributes === []) {
            // Matches the legacy JWTPrimary::$syncAttributes default.
            $this->managedAttributes = ['email', 'username'];
        }
        if ($this->bypassApproval && $this->trustedAuthClientIds === []) {
            $this->trustedAuthClientIds = [self::SOURCE_ID];
        }
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getTitle(): string
    {
        return $this->title !== '' ? $this->title : 'JWT SSO';
    }

    /**
     * JWT tokens may not always carry a `username` claim — auto-generate when
     * absent, fall back to email-derived value.
     */
    public function getUsernameStrategy(): string
    {
        return UserSourceInterface::USERNAME_AUTO_GENERATE;
    }

    /**
     * Creates a HumHub user with user_source = 'jwt'.
     *
     * Does NOT record a user_auth row — the caller (AuthClientService) owns
     * that and writes the right source_id for the actual auth client.
     */
    public function createUser(array $attributes): ?User
    {
        $registration = $this->buildRegistration($attributes);
        if ($registration === null) {
            return null;
        }

        $registration->getUser()->user_source = $this->getId();

        if (!$registration->register()) {
            Yii::warning(
                'JwtUserSource (' . $this->getId() . '): could not create user. Errors: '
                . VarDumper::dumpAsString($registration->getErrors()),
                'jwt-sso',
            );
            return null;
        }

        return $registration->getUser();
    }

    private function buildRegistration(array $attributes): ?Registration
    {
        $registration = new Registration(enableEmailField: true, enablePasswordForm: false);
        $registration->enableUserApproval = $this->requiresApproval(self::SOURCE_ID);

        unset(
            $attributes['id'],
            $attributes['guid'],
            $attributes['contentcontainer_id'],
            $attributes['user_source'],
            $attributes['status'],
        );

        if (empty($attributes['username'])) {
            $resolved = $this->getUsernameResolver()->resolve($attributes, $this->getUsernameStrategy());
            if ($resolved === null) {
                return null;
            }
            $attributes['username'] = $resolved;
        }

        $registration->getUser()->setAttributes($attributes, false);
        $registration->getProfile()->setAttributes($attributes, false);
        $registration->getGroupUser()->setAttributes($attributes, false);
        $registration->setModels();

        return $registration;
    }
}
