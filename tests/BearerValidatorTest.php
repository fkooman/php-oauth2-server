<?php

/*
 * Copyright (c) 2017, 2018 François Kooman <fkooman@tuxed.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

namespace fkooman\OAuth\Server\Tests;

use DateTime;
use fkooman\OAuth\Server\ArrayClientDb;
use fkooman\OAuth\Server\BearerValidator;
use fkooman\OAuth\Server\Exception\InvalidTokenException;
use fkooman\OAuth\Server\Json;
use fkooman\OAuth\Server\OAuthServer;
use fkooman\OAuth\Server\PdoStorage;
use fkooman\OAuth\Server\ResourceOwner;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PDO;
use PHPUnit\Framework\TestCase;

class BearerValidatorTest extends TestCase
{
    /** @var \fkooman\OAuth\Server\BearerValidator */
    private $validator;

    /** @var \fkooman\OAuth\Server\PdoStorage */
    private $storage;

    public function setUp()
    {
        $clientDb = new ArrayClientDb(
            [
                'code-client' => [
                    'redirect_uri_list' => ['http://example.org/code-cb'],
                    'display_name' => 'Code Client',
                    'client_secret' => null,
                    'require_approval' => true,
                ],
            ]
        );
        $this->storage = new PdoStorage(new PDO('sqlite::memory:'));
        $this->storage->init();
        $this->validator = new BearerValidator(
            $this->storage,
            $clientDb,
            new TestSigner()
        );
        $this->validator->setDateTime(new DateTime('2016-01-01'));
    }

    public function testValidToken()
    {
        $this->storage->storeAuthorization('foo', 'code-client', 'config', 'random_1');

        $providedAccessToken = Base64UrlSafe::encodeUnpadded(
            Json::encode(
                [
                    'v' => OAuthServer::TOKEN_VERSION,
                    'type' => 'access_token',
                    'auth_key' => 'random_1',
                    'resource_owner' => self::encodeResourceOwner('foo'),
                    'client_id' => 'code-client',
                    'scope' => 'config',
                    'authz_expires_at' => '2017-01-01T00:00:00+00:00',
                    'expires_at' => '2016-01-01T01:00:00+00:00',
                ]
            )
        );
        $accessTokenInfo = $this->validator->validate(\sprintf('Bearer %s', $providedAccessToken));
        $this->assertSame('foo', $accessTokenInfo->getResourceOwner()->getUserId());
        $this->assertNull($accessTokenInfo->getResourceOwner()->getExtData());
        $this->assertSame('2017-01-01T00:00:00+00:00', $accessTokenInfo->getAuthzExpiresAt()->format(DateTime::ATOM));
        $this->assertSame('config', (string) $accessTokenInfo->getScope());
    }

    public function testInvalidSignature()
    {
        try {
            $providedAccessToken = Base64UrlSafe::encodeUnpadded(
                Json::encode(
                    [
                        'v' => OAuthServer::TOKEN_VERSION,
                        'type' => 'access_token',
                        'auth_key' => 'invalid_sig',
                        'resource_owner' => self::encodeResourceOwner('foo'),
                        'client_id' => 'code-client',
                        'scope' => 'config',
                        'authz_expires_at' => '2017-01-01T00:00:00+00:00',
                        'expires_at' => '2016-01-01T01:00:00+00:00',
                    ]
                )
            );

            $this->storage->storeAuthorization('foo', 'code-client', 'config', 'random_1');
            $this->validator->validate(\sprintf('Bearer %s', $providedAccessToken));
            $this->fail();
        } catch (InvalidTokenException $e) {
            $this->assertSame('"access_token" has invalid signature', $e->getDescription());
        }
    }

    public function testDeletedClient()
    {
        try {
            $this->validator = new BearerValidator(
                $this->storage,
                new ArrayClientDb([]),
                new TestSigner()
            );
            $this->validator->setDateTime(new DateTime('2016-01-01'));

            $providedAccessToken = Base64UrlSafe::encodeUnpadded(
                Json::encode(
                    [
                        'v' => OAuthServer::TOKEN_VERSION,
                        'type' => 'access_token',
                        'auth_key' => 'random_1',
                        'resource_owner' => self::encodeResourceOwner('foo'),
                        'client_id' => 'code-client',
                        'scope' => 'config',
                        'authz_expires_at' => '2017-01-01T00:00:00+00:00',
                        'expires_at' => '2016-01-01T01:00:00+00:00',
                    ]
                )
            );

            $this->validator->validate(\sprintf('Bearer %s', $providedAccessToken));
            $this->fail();
        } catch (InvalidTokenException $e) {
            $this->assertSame('client "code-client" no longer registered', $e->getDescription());
        }
    }

    public function testInvalidSyntax()
    {
        try {
            $this->validator->validate('Bearer %%%%');
            $this->fail();
        } catch (InvalidTokenException $e) {
            $this->assertSame('invalid Bearer token', $e->getDescription());
        }
    }

    public function testExpiredToken()
    {
        $providedAccessToken = Base64UrlSafe::encodeUnpadded(
            Json::encode(
                [
                    'v' => OAuthServer::TOKEN_VERSION,
                    'type' => 'access_token',
                    'auth_key' => 'random_1',
                    'resource_owner' => self::encodeResourceOwner('foo'),
                    'client_id' => 'code-client',
                    'scope' => 'config',
                    'authz_expires_at' => '2017-01-01T00:00:00+00:00',
                    'expires_at' => '2015-01-01T01:00:00+00:00',
                ]
            )
        );

        try {
            $this->validator->validate(\sprintf('Bearer %s', $providedAccessToken));
            $this->fail();
        } catch (InvalidTokenException $e) {
            $this->assertSame('"access_token" expired', $e->getDescription());
        }
    }

    public function testBasicAuthentication()
    {
        try {
            $this->validator->validate('Basic AAA==');
            $this->fail();
        } catch (InvalidTokenException $e) {
            $this->assertSame('invalid Bearer token', $e->getDescription());
        }
    }

    public function testCodeAsAccessToken()
    {
        try {
            $providedAccessToken = Base64UrlSafe::encodeUnpadded(
                Json::encode(
                    [
                        'v' => OAuthServer::TOKEN_VERSION,
                        'type' => 'authorization_code',
                        'auth_key' => 'random_1',
                        'resource_owner' => self::encodeResourceOwner('foo'),
                        'client_id' => 'code-client',
                        'scope' => 'config',
                        'redirect_uri' => 'http://example.org/code-cb',
                        'code_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
                        'authz_expires_at' => '2017-01-01T00:00:00+00:00',
                        'expires_at' => '2016-01-01T00:05:00+00:00',
                    ]
                )
            );

            $this->validator->validate(\sprintf('Bearer %s', $providedAccessToken));
            $this->fail();
        } catch (InvalidTokenException $e) {
            $this->assertSame('expected "access_token", got "authorization_code"', $e->getDescription());
        }
    }

    /**
     * @param string $userId
     *
     * @return string
     */
    private static function encodeResourceOwner($userId)
    {
        $resourceOwner = new ResourceOwner($userId);

        return $resourceOwner->encode();
    }
}
