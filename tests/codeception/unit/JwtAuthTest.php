<?php

namespace tests\codeception\unit;

use humhub\modules\sso\jwt\authclient\JWT;
use tests\codeception\_support\HumHubDbTestCase;
use Yii;

/**
 * Unit tests for {@see JWT} — attribute normalisation, JWT meta-claim
 * stripping, and IP allow-list logic.
 *
 * No real JWT broker or HTTP request is required.
 */
class JwtAuthTest extends HumHubDbTestCase
{
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
    // getId() defaults
    // ---------------------------------------------------------------------------

    public function testDefaultClientIdIsJwt(): void
    {
        $client = $this->makeJwt();

        $this->assertSame('jwt', $client->getId());
    }
}
