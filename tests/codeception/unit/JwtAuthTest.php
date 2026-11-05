<?php

namespace tests\codeception\unit;

use Firebase\JWT\JWT as FirebaseJWT;
use humhub\modules\sso\jwt\authclient\JWT;
use tests\codeception\_support\HumHubDbTestCase;
use Yii;
use yii\helpers\Url;

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

    private const KEY = 'test-shared-key-test-shared-key-test-shared-key';

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
    // getId() defaults
    // ---------------------------------------------------------------------------

    public function testDefaultClientIdIsJwt(): void
    {
        $client = $this->makeJwt();

        $this->assertSame('jwt', $client->getId());
    }
}
