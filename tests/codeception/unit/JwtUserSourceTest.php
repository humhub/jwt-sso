<?php

namespace tests\codeception\unit;

use humhub\modules\sso\jwt\source\JwtUserSource;
use humhub\modules\user\models\User;
use humhub\modules\user\source\UserSourceInterface;
use tests\codeception\_support\HumHubDbTestCase;

/**
 * Unit tests for {@see JwtUserSource}.
 *
 * Covers init-time defaults, attribute lock-down, approval routing, and
 * createUser() integration with Registration.
 */
class JwtUserSourceTest extends HumHubDbTestCase
{
    private function makeSource(array $config = []): JwtUserSource
    {
        $source = new JwtUserSource($config);
        $source->init();
        return $source;
    }

    // ---------------------------------------------------------------------------
    // init() defaults
    // ---------------------------------------------------------------------------

    public function testIdDefaultsToConstant(): void
    {
        $source = $this->makeSource();

        $this->assertSame(JwtUserSource::SOURCE_ID, $source->getId());
        $this->assertSame('jwt', $source->getId());
    }

    public function testAllowedAuthClientIdsDefaultsToOwnId(): void
    {
        $source = $this->makeSource();

        $this->assertSame(['jwt'], $source->getAllowedAuthClientIds());
    }

    public function testManagedAttributesDefaultsToEmailAndUsername(): void
    {
        $source = $this->makeSource();

        $this->assertSame(['email', 'username'], $source->getManagedAttributes());
    }

    public function testManagedAttributesIsConfigurable(): void
    {
        $source = $this->makeSource([
            'managedAttributes' => ['email', 'firstname', 'lastname'],
        ]);

        $this->assertSame(['email', 'firstname', 'lastname'], $source->getManagedAttributes());
    }

    public function testUsernameStrategyIsAutoGenerate(): void
    {
        $source = $this->makeSource();

        $this->assertSame(UserSourceInterface::USERNAME_AUTO_GENERATE, $source->getUsernameStrategy());
    }

    public function testDefaultTitleFallsBackToJwtSso(): void
    {
        $source = $this->makeSource();

        $this->assertSame('JWT SSO', $source->getTitle());
    }

    public function testConfiguredTitleWins(): void
    {
        $source = $this->makeSource(['title' => 'Acme JWT']);

        $this->assertSame('Acme JWT', $source->getTitle());
    }

    // ---------------------------------------------------------------------------
    // bypassApproval wiring
    // ---------------------------------------------------------------------------

    public function testApprovalIsRequiredByDefaultWhenApprovalIsTrue(): void
    {
        $source = $this->makeSource(['approval' => true]);

        // Without trustedAuthClientIds, calling for the own auth client must
        // still require approval.
        $this->assertTrue($source->requiresApproval('jwt'));
    }

    public function testBypassApprovalTrustsTheOwnAuthClient(): void
    {
        $source = $this->makeSource([
            'approval' => true,
            'bypassApproval' => true,
        ]);

        // bypassApproval = true populates trustedAuthClientIds with ['jwt'],
        // so requiresApproval('jwt') short-circuits to false even though
        // $approval = true.
        $this->assertFalse($source->requiresApproval('jwt'));

        // ... but the form flow (null clientId) still goes through approval.
        $this->assertTrue($source->requiresApproval(null));
    }

    // ---------------------------------------------------------------------------
    // claimsUserCreation() — declarative allow-list match
    // ---------------------------------------------------------------------------

    public function testClaimsUserCreationForOwnAuthClient(): void
    {
        $source = $this->makeSource();

        $this->assertTrue($source->claimsUserCreation('jwt', ['email' => 'x@y.z']));
    }

    public function testDoesNotClaimUserCreationForForeignAuthClient(): void
    {
        $source = $this->makeSource();

        $this->assertFalse($source->claimsUserCreation('local', ['email' => 'x@y.z']));
    }

    // ---------------------------------------------------------------------------
    // createUser() — full provisioning round-trip
    // ---------------------------------------------------------------------------

    public function testCreateUserPersistsWithJwtSource(): void
    {
        $source = $this->makeSource();

        $user = $source->createUser([
            'email' => 'dora@example.org',
            'username' => 'dora',
            'firstname' => 'Dora',
            'lastname' => 'Example',
        ]);

        $this->assertNotNull($user);
        $this->assertInstanceOf(User::class, $user);
        $this->assertSame('jwt', $user->user_source);
        $this->assertSame('dora@example.org', $user->email);
        $this->assertSame('dora', $user->username);
    }

    public function testCreateUserAutoGeneratesUsernameWhenMissing(): void
    {
        $source = $this->makeSource();

        $user = $source->createUser([
            'email' => 'no.username@example.org',
            'firstname' => 'No',
            'lastname' => 'Username',
        ]);

        $this->assertNotNull($user);
        // Username strategy is AUTO_GENERATE — UsernameResolver derives a
        // non-empty value from the supplied attributes.
        $this->assertNotEmpty($user->username);
    }

    public function testCreateUserStripsSystemManagedKeys(): void
    {
        $source = $this->makeSource();

        $user = $source->createUser([
            'email' => 'evan@example.org',
            'username' => 'evan',
            'firstname' => 'Evan',
            'lastname' => 'Example',
            // These keys must NOT be set on the user — they're system-managed.
            'id' => 99999,
            'guid' => 'attacker-guid',
            'user_source' => 'attacker-source',
            'status' => User::STATUS_DISABLED,
        ]);

        $this->assertNotNull($user);
        $this->assertNotSame(99999, $user->id);
        $this->assertNotSame('attacker-guid', $user->guid);
        $this->assertSame('jwt', $user->user_source);
        $this->assertNotSame(User::STATUS_DISABLED, $user->status);
    }

    public function testCreateUserReturnsNullWhenRequiredFieldsMissing(): void
    {
        $source = $this->makeSource();

        // No email — Registration validation must fail and createUser returns null.
        $user = $source->createUser([
            'firstname' => 'Only',
            'lastname' => 'Names',
        ]);

        $this->assertNull($user);
    }
}
