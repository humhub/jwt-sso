<?php

namespace tests\codeception\unit;

use Firebase\JWT\JWT as FirebaseJWT;
use humhub\modules\sso\jwt\authclient\JWT;
use humhub\modules\sso\jwt\source\JwtUserSource;
use humhub\modules\user\models\Group;
use humhub\modules\user\models\GroupUser;
use humhub\modules\user\models\User;
use humhub\modules\user\source\UserSourceInterface;
use tests\codeception\_support\HumHubDbTestCase;
use Yii;
use yii\base\Application;
use yii\helpers\Url;
use yii\log\Logger;

/**
 * Unit tests for {@see JWT} — attribute normalisation, JWT meta-claim
 * stripping, and IP allow-list logic.
 *
 * No real JWT broker or HTTP request is required.
 */
class JwtAuthTest extends HumHubDbTestCase
{
    /**
     * The default fixtures provide the users needed to test the handling of already logged-in users.
     */
    protected $fixtureConfig = ['default'];

    private const KEY = 'test-shared-key-test-shared-key-test-shared-key';
    private const DEFAULT_GROUP_ID = 2; // "Users", default group, shown at registration
    private const PRIVATE_GROUP_ID = 3; // "Moderators", not shown at registration

    protected function tearDown(): void
    {
        JWT::detachRegistrationGroupsHandler();
        Yii::$app->off(Application::EVENT_AFTER_REQUEST, [JWT::class, 'detachRegistrationGroupsHandler']);
        parent::tearDown();
    }

    private function makeJwt(array $config = []): JWT
    {
        $client = new JWT($config);
        $client->init();
        return $client;
    }

    // ---------------------------------------------------------------------------
    // setUserAttributes(): meta-claim stripping
    // ---------------------------------------------------------------------------

    public function testJwtMetaClaimsAreStripped(): void
    {
        $client = $this->makeJwt();
        $client->setUserAttributes([
            'iss' => 'https://broker.example',
            'jti' => 'token-123',
            'iat' => time(),
            'email' => 'alice@example.org',
            'username' => 'alice',
        ]);

        $attrs = $client->getUserAttributes();

        $this->assertArrayNotHasKey('iss', $attrs);
        $this->assertArrayNotHasKey('jti', $attrs);
        $this->assertArrayNotHasKey('iat', $attrs);
        $this->assertSame('alice@example.org', $attrs['email']);
        $this->assertSame('alice', $attrs['username']);
    }

    // ---------------------------------------------------------------------------
    // setUserAttributes(): id-attribute mapping
    // ---------------------------------------------------------------------------

    public function testIdIsDerivedFromEmailWhenIdAttributeIsEmail(): void
    {
        $client = $this->makeJwt(['idAttribute' => 'email']);
        $client->setUserAttributes([
            'email' => 'alice@example.org',
            'username' => 'alice',
        ]);

        $attrs = $client->getUserAttributes();

        $this->assertSame('alice@example.org', $attrs['id']);
    }

    public function testIdIsDerivedFromUsernameWhenIdAttributeIsUsername(): void
    {
        $client = $this->makeJwt(['idAttribute' => 'username']);
        // No explicit 'id' in the payload — the client should fall back to
        // setting the username key (which is what the legacy behaviour did).
        $client->setUserAttributes([
            'email' => 'bob@example.org',
            'username' => 'bob',
        ]);

        $attrs = $client->getUserAttributes();

        // Legacy semantics: when idAttribute is 'username' or 'guid', the
        // client leaves `id` unset but keeps the relevant key.
        $this->assertArrayNotHasKey('id', $attrs);
        $this->assertSame('bob', $attrs['username']);
    }

    public function testExplicitIdInPayloadIsPreserved(): void
    {
        $client = $this->makeJwt(['idAttribute' => 'email']);
        $client->setUserAttributes([
            'id' => 'subject-uuid-42',
            'email' => 'carol@example.org',
        ]);

        $attrs = $client->getUserAttributes();

        // The explicit 'id' must NOT be overwritten by the idAttribute mapping.
        $this->assertSame('subject-uuid-42', $attrs['id']);
    }

    // ---------------------------------------------------------------------------
    // checkIPAccess(): wildcard and exact match
    // ---------------------------------------------------------------------------

    public function testCheckIpAccessReturnsTrueWhenAllowedIpsIsEmpty(): void
    {
        $client = $this->makeJwt(['allowedIPs' => []]);

        $this->assertTrue($client->checkIPAccess());
    }

    public function testCheckIpAccessAllowsExactMatch(): void
    {
        Yii::$app->request->setBodyParams([]);
        $_SERVER['REMOTE_ADDR'] = '10.0.0.5';

        $client = $this->makeJwt(['allowedIPs' => ['10.0.0.5']]);

        $this->assertTrue($client->checkIPAccess());
    }

    public function testCheckIpAccessDeniesMismatch(): void
    {
        $_SERVER['REMOTE_ADDR'] = '10.0.0.5';

        $client = $this->makeJwt(['allowedIPs' => ['192.168.1.1']]);

        $this->assertFalse($client->checkIPAccess());
    }

    public function testCheckIpAccessAllowsWildcardPrefix(): void
    {
        $_SERVER['REMOTE_ADDR'] = '192.168.1.42';

        $client = $this->makeJwt(['allowedIPs' => ['192.168.1.*']]);

        $this->assertTrue($client->checkIPAccess());
    }

    public function testCheckIpAccessAllowsGlobalWildcard(): void
    {
        $_SERVER['REMOTE_ADDR'] = '203.0.113.99';

        $client = $this->makeJwt(['allowedIPs' => ['*']]);

        $this->assertTrue($client->checkIPAccess());
    }

    // ---------------------------------------------------------------------------
    // handleAuthRequest(): session handling, IP restriction, token lifetime
    // ---------------------------------------------------------------------------

    private function makeToken(array $claims = [], string $key = self::KEY): string
    {
        return FirebaseJWT::encode($claims + ['email' => 'alice@example.org'], $key, 'HS256');
    }

    private function makeAuthClient(array $config = []): JWT
    {
        return $this->makeJwt($config + ['sharedKey' => self::KEY, 'url' => 'https://broker.example/']);
    }

    private function handle(JWT $client, ?string $token): ?\yii\web\Response
    {
        Yii::$app->request->setQueryParams($token === null ? [] : ['jwt' => $token]);
        $_SERVER['REMOTE_ADDR'] = '10.0.0.5';

        return $client->handleAuthRequest();
    }

    public function testValidTokenIsAccepted(): void
    {
        $client = $this->makeAuthClient();

        $this->assertNull($this->handle($client, $this->makeToken(['exp' => time() + 200])));
        $this->assertSame('alice@example.org', $client->getUserAttributes()['email']);
    }

    public function testInvalidTokensRedirectToLogin(): void
    {
        $client = $this->makeAuthClient();
        $invalid = [
            'garbage',
            $this->makeToken(['exp' => time() - 3600]),
            $this->makeToken(['exp' => time() + 200], 'another-key-another-key-another-key-another-key'),
        ];

        foreach ($invalid as $token) {
            $response = $this->handle($client, $token);
            $this->assertNotNull($response);
            $this->assertSame(Url::to(['/user/auth/login'], true), $response->headers->get('Location'));
        }
    }

    public function testInvalidTokenKeepsLoggedInUser(): void
    {
        $this->becomeUser('User1');
        $client = $this->makeAuthClient();

        foreach (['garbage', $this->makeToken(['exp' => time() - 3600])] as $token) {
            $this->assertNotNull($this->handle($client, $token));
            $this->assertFalse(Yii::$app->user->isGuest);
        }
    }

    public function testMissingTokenKeepsLoggedInUser(): void
    {
        $this->becomeUser('User1');

        $this->assertNotNull($this->handle($this->makeAuthClient(), null));
        $this->assertFalse(Yii::$app->user->isGuest);
    }

    public function testValidTokenLogsOutCurrentUser(): void
    {
        $this->becomeUser('User1');

        $this->assertNull($this->handle($this->makeAuthClient(), $this->makeToken(['exp' => time() + 200])));
        $this->assertTrue(Yii::$app->user->isGuest);
    }

    public function testNotAllowedIpKeepsLoggedInUser(): void
    {
        $this->becomeUser('User1');
        $client = $this->makeAuthClient(['allowedIPs' => ['192.168.1.*']]);

        $response = $this->handle($client, $this->makeToken(['exp' => time() + 200]));

        $this->assertNotNull($response);
        $this->assertSame(Url::to(['/user/auth/login'], true), $response->headers->get('Location'));
        $this->assertFalse(Yii::$app->user->isGuest);
    }

    public function testAllowedIpAcceptsToken(): void
    {
        $client = $this->makeAuthClient(['allowedIPs' => ['10.0.0.*']]);

        $this->assertNull($this->handle($client, $this->makeToken(['exp' => time() + 200])));
    }

    public function testTokenWithoutExpIsAcceptedByDefault(): void
    {
        $this->assertNull($this->handle($this->makeAuthClient(), $this->makeToken()));
    }

    public function testMaxTokenAgeRejectsTokenWithoutExp(): void
    {
        $client = $this->makeAuthClient(['maxTokenAge' => 300]);

        $response = $this->handle($client, $this->makeToken());

        $this->assertNotNull($response);
        $this->assertSame(Url::to(['/user/auth/login'], true), $response->headers->get('Location'));
    }

    public function testMaxTokenAgeRejectsTooDistantExp(): void
    {
        $client = $this->makeAuthClient(['maxTokenAge' => 300, 'leeway' => 60]);

        $this->assertNotNull($this->handle($client, $this->makeToken(['exp' => time() + 3600])));
        $this->assertNotNull($this->handle($client, $this->makeToken(['exp' => time() + 400])));
    }

    public function testMaxTokenAgeAcceptsExpWithinLimit(): void
    {
        $client = $this->makeAuthClient(['maxTokenAge' => 300, 'leeway' => 60]);

        $this->assertNull($this->handle($client, $this->makeToken(['exp' => time() + 200])));
        $this->assertNull($this->handle($client, $this->makeToken(['exp' => time() + 300])));
    }

    // ---------------------------------------------------------------------------
    // assignableGroupIds: group_id claim
    // ---------------------------------------------------------------------------

    private function registrationGroupIdsAfterToken(array $config, $groupId): array
    {
        $this->assertNull($this->handle($this->makeAuthClient($config), $this->makeToken(['group_id' => $groupId])));

        return $this->registrationGroupIds();
    }

    public function testGroupClaimDoesNotChangeRegistrationGroupsByDefault(): void
    {
        $this->assertNotContains(self::PRIVATE_GROUP_ID, $this->registrationGroupIdsAfterToken([], self::PRIVATE_GROUP_ID));
    }

    public function testAssignableGroupClaimMakesTheGroupARegistrationGroup(): void
    {
        $this->assertContains(self::PRIVATE_GROUP_ID, $this->registrationGroupIdsAfterToken(['assignableGroupIds' => [self::PRIVATE_GROUP_ID]], self::PRIVATE_GROUP_ID));
        $this->assertContains(self::PRIVATE_GROUP_ID, $this->registrationGroupIdsAfterToken(['assignableGroupIds' => ['3']], '3'));
    }

    public function testUnlistedMissingOrInvalidGroupClaimDoesNotChangeRegistrationGroups(): void
    {
        $config = ['assignableGroupIds' => [self::PRIVATE_GROUP_ID, 999]];

        foreach ([4, 999, '3abc', [self::PRIVATE_GROUP_ID], null] as $claim) {
            $groupIds = $this->registrationGroupIdsAfterToken($config, $claim);
            $this->assertNotContains(self::PRIVATE_GROUP_ID, $groupIds);
            $this->assertNotContains(4, $groupIds);
            $this->assertNotContains(999, $groupIds);
        }
    }

    public function testAdministratorGroupCannotBeAssigned(): void
    {
        $this->assertNotContains(1, $this->registrationGroupIdsAfterToken(['assignableGroupIds' => [1]], 1));
    }

    public function testGroupIsNoRegistrationGroupAfterTheRequest(): void
    {
        $config = ['assignableGroupIds' => [self::PRIVATE_GROUP_ID]];
        $this->assertContains(self::PRIVATE_GROUP_ID, $this->registrationGroupIdsAfterToken($config, self::PRIVATE_GROUP_ID));

        Yii::$app->trigger(Application::EVENT_AFTER_REQUEST);

        $this->assertNotContains(self::PRIVATE_GROUP_ID, $this->registrationGroupIds());
    }

    public function testGroupClaimIsKeptInUserAttributes(): void
    {
        $client = $this->makeAuthClient(['assignableGroupIds' => [self::PRIVATE_GROUP_ID]]);
        $this->assertNull($this->handle($client, $this->makeToken(['group_id' => 4])));

        $this->assertSame(4, $client->getUserAttributes()['group_id']);
    }

    public function testGroupIsNotARegistrationGroupWithoutVerifiedToken(): void
    {
        $client = $this->makeAuthClient(['assignableGroupIds' => [self::PRIVATE_GROUP_ID]]);
        // Restoring attributes (e.g. from the session) must not open the group for the registration form
        $client->setUserAttributes(['email' => 'alice@example.org', 'group_id' => self::PRIVATE_GROUP_ID]);

        $this->assertNotContains(self::PRIVATE_GROUP_ID, $this->registrationGroupIds());
    }

    public function testVerifiedTokenMakesOnlyTheClaimedGroupARegistrationGroup(): void
    {
        $client = $this->makeAuthClient(['assignableGroupIds' => [self::PRIVATE_GROUP_ID, 4]]);
        $this->assertNull($this->handle($client, $this->makeToken(['group_id' => self::PRIVATE_GROUP_ID])));

        $this->assertContains(self::PRIVATE_GROUP_ID, $this->registrationGroupIds());
        $this->assertNotContains(4, $this->registrationGroupIds());

        // A following token without group claim removes it again
        $this->assertNull($this->handle($client, $this->makeToken()));
        $this->assertNotContains(self::PRIVATE_GROUP_ID, $this->registrationGroupIds());
    }

    public function testNewUserIsAddedToClaimedGroupWithLocalUserSource(): void
    {
        $user = $this->createUserFromToken(Yii::$app->userSourceCollection->getLocalUserSource(), ['group_id' => self::PRIVATE_GROUP_ID]);

        $this->assertSame([self::PRIVATE_GROUP_ID], $this->groupIdsOf($user));
    }

    public function testNewUserIsAddedToClaimedGroupWithJwtUserSource(): void
    {
        $user = $this->createUserFromToken(new JwtUserSource(), ['group_id' => self::PRIVATE_GROUP_ID]);

        $this->assertSame([self::PRIVATE_GROUP_ID], $this->groupIdsOf($user));
    }

    public function testNewUserIsAddedToClaimedGroupWhenGroupSelectionIsShownAtRegistration(): void
    {
        Yii::$app->getModule('user')->settings->set('auth.showRegistrationUserGroup', true);

        $user = $this->createUserFromToken(new JwtUserSource(), ['group_id' => self::PRIVATE_GROUP_ID]);

        $this->assertSame([self::PRIVATE_GROUP_ID], $this->groupIdsOf($user));
    }

    public function testNewUserWithoutGroupClaimGetsDefaultGroup(): void
    {
        $this->assertSame([self::DEFAULT_GROUP_ID], $this->groupIdsOf($this->createUserFromToken(new JwtUserSource(), [])));
    }

    public function testNewUserIsAddedToUnlistedClaimedGroupShownAtRegistration(): void
    {
        // Behaviour without assignableGroupIds: a registration group of the claim is accepted
        Yii::$app->getModule('user')->settings->set('auth.showRegistrationUserGroup', true);
        Group::updateAll(['show_at_registration' => 1], ['id' => 4]);

        $user = $this->createUserFromToken(Yii::$app->userSourceCollection->getLocalUserSource(), ['group_id' => 4]);

        $this->assertSame([4], $this->groupIdsOf($user));
    }

    public function testNewUserWithUnlistedNonRegistrationGroupClaimGetsNoGroup(): void
    {
        // Core behaviour, documented in the manual: the claim prevents the default group, and the group is not accepted
        foreach ([false, true] as $i => $showGroupSelection) {
            Yii::$app->getModule('user')->settings->set('auth.showRegistrationUserGroup', $showGroupSelection);
            Group::updateAll(['show_at_registration' => (int) $showGroupSelection], ['id' => self::PRIVATE_GROUP_ID]);

            $user = $this->createUserFromToken(Yii::$app->userSourceCollection->getLocalUserSource(), ['group_id' => 4], 'jwtuser' . $i);

            $this->assertSame([], $this->groupIdsOf($user));
        }
    }

    public function testWarningIsLoggedForUnlistedNonRegistrationGroupClaim(): void
    {
        static::logInitialize();
        $config = ['assignableGroupIds' => [self::PRIVATE_GROUP_ID]];

        $this->registrationGroupIdsAfterToken($config, self::DEFAULT_GROUP_ID); // unlisted, but a registration group
        static::assertNotLogRegex('/group_id claim/', Logger::LEVEL_WARNING, ['jwt-sso']);

        foreach ([0, '0', '', false] as $claim) { // empty: the registration assigns the default group
            $this->registrationGroupIdsAfterToken($config, $claim);
        }
        static::assertNotLogRegex('/group_id claim/', Logger::LEVEL_WARNING, ['jwt-sso']);

        $this->registrationGroupIdsAfterToken($config, 4);
        static::assertLogRegex('/group 4 of the group_id claim/', Logger::LEVEL_WARNING, ['jwt-sso']);
    }

    private function createUserFromToken(UserSourceInterface $source, array $claims, string $name = 'jwtuser'): User
    {
        $client = $this->makeAuthClient(['assignableGroupIds' => [self::PRIVATE_GROUP_ID]]);
        $this->assertNull($this->handle($client, $this->makeToken($claims + ['email' => $name . '@example.org', 'username' => $name, 'firstname' => 'Jwt', 'lastname' => 'User'])));

        $user = $source->createUser($client->getUserAttributes());
        $this->assertNotNull($user);

        return $user;
    }

    private function groupIdsOf(User $user): array
    {
        $ids = array_map('intval', GroupUser::find()->select('group_id')->where(['user_id' => $user->id])->column());
        sort($ids);

        return $ids;
    }

    private function registrationGroupIds(): array
    {
        return array_map(fn(Group $group) => (int) $group->id, Group::getRegistrationGroups());
    }

    // ---------------------------------------------------------------------------
    // getId() defaults
    // ---------------------------------------------------------------------------

    public function testDefaultClientIdIsJwt(): void
    {
        $client = $this->makeJwt();

        $this->assertSame('jwt', $client->getId());
    }
}
