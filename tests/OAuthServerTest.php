<?php

/*
 * Copyright (c) 2017-2020 François Kooman <fkooman@tuxed.net>
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
use fkooman\OAuth\Server\Exception\InvalidClientException;
use fkooman\OAuth\Server\Exception\InvalidGrantException;
use fkooman\OAuth\Server\Exception\InvalidRequestException;
use fkooman\OAuth\Server\Json;
use fkooman\OAuth\Server\OAuthServer;
use fkooman\OAuth\Server\PdoStorage;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PDO;
use PHPUnit\Framework\TestCase;

class OAuthServerTest extends TestCase
{
    /** @var \fkooman\OAuth\Server\StorageInterface */
    private $storage;

    /** @var \fkooman\OAuth\Server\OAuthServer */
    private $server;

    /**
     * @return void
     */
    public function setUp()
    {
        $clientDb = new ArrayClientDb(
            [
                'code-client' => [
                    'redirect_uri_list' => ['http://example.org/code-cb'],
                    'display_name' => 'Code Client',
                    'require_approval' => false,
                    'client_secret' => null,
                ],
                'code-client-query-redirect' => [
                    'redirect_uri_list' => ['http://example.org/code-cb?keep=this'],
                    'display_name' => 'Code Client',
                    'client_secret' => null,
                    'require_approval' => true,
                ],
                'code-client-secret' => [
                    'redirect_uri_list' => ['http://example.org/code-cb'],
                    'display_name' => 'Code Client',
                    'client_secret' => '123456',
                    'require_approval' => true,
                ],
                'loopback' => [
                    'redirect_uri_list' => ['http://127.0.0.1:{PORT}/cb'],
                    'display_name' => 'Loopback Client',
                    'client_secret' => null,
                    'require_approval' => true,
                ],
            ]
        );

        $this->storage = new PdoStorage(new PDO('sqlite::memory:'));
        $this->storage->init();
        $this->server = new OAuthServer(
            $this->storage,
            $clientDb,
            new TestSigner()
        );
        $this->server->setDateTime(new DateTime('2016-01-01'));
        $this->server->setRandom(new TestRandom());
    }

    /**
     * @return void
     */
    public function testAuthorizeCode()
    {
        $this->assertSame(
            [
                'client_id' => 'code-client',
                'display_name' => 'Code Client',
                'scope' => 'config',
                'redirect_uri' => 'http://example.org/code-cb',
            ],
            $this->server->getAuthorize(
                [
                    'client_id' => 'code-client',
                    'redirect_uri' => 'http://example.org/code-cb',
                    'response_type' => 'code',
                    'scope' => 'config',
                    'state' => '12345',
                    'code_challenge_method' => 'S256',
                    'code_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
                ]
            )
        );
    }

    /**
     * @return void
     */
    public function testAuthorizeCodeNoCodeChallenge()
    {
        try {
            $this->assertSame(
                [
                    'client_id' => 'code-client',
                    'display_name' => 'Code Client',
                    'scope' => 'config',
                    'redirect_uri' => 'http://example.org/code-cb',
                ],
                $this->server->getAuthorize(
                    [
                        'client_id' => 'code-client',
                        'redirect_uri' => 'http://example.org/code-cb',
                        'response_type' => 'code',
                        'scope' => 'config',
                        'state' => '12345',
                    ]
                )
            );
        } catch (InvalidRequestException $e) {
            $this->assertSame('missing "code_challenge_method" parameter', $e->getDescription());
        }
    }

    /**
     * @return void
     */
    public function testGetAuthorizeResponse()
    {
        $authorizeResponse = $this->server->getAuthorizeResponse(
            [
                'client_id' => 'code-client',
                'redirect_uri' => 'http://example.org/code-cb',
                'response_type' => 'code',
                'scope' => 'config',
                'state' => '12345',
                'code_challenge_method' => 'S256',
                'code_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            ],
            'foo'
        );

        $expectedCode = Base64UrlSafe::encodeUnpadded(
            Json::encode(
                [
                    'v' => OAuthServer::TOKEN_VERSION,
                    'type' => 'authorization_code',
                    'auth_key' => 'random_1',
                    'user_id' => 'foo',
                    'client_id' => 'code-client',
                    'scope' => 'config',
                    'redirect_uri' => 'http://example.org/code-cb',
                    'code_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
                    'expires_at' => '2016-01-01T00:05:00+00:00',
                ]
            )
        );

        $this->assertInstanceOf('\fkooman\OAuth\Server\Http\Response', $authorizeResponse);
        $this->assertSame(
            [
                'Location' => \sprintf('http://example.org/code-cb?code=%s&state=12345', $expectedCode),
                'Content-Type' => 'text/html; charset=utf-8',
            ],
            $authorizeResponse->getHeaders()
        );
    }

    /**
     * @return void
     */
    public function testAuthorizeCodePost()
    {
        $authorizeResponse = $this->server->postAuthorize(
            [
                'client_id' => 'code-client',
                'redirect_uri' => 'http://example.org/code-cb',
                'response_type' => 'code',
                'scope' => 'foo',
                'state' => '12345',
                'code_challenge_method' => 'S256',
                'code_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            ],
            [
                'approve' => 'yes',
            ],
            'foo'
        );
        $this->assertSame(302, $authorizeResponse->getStatusCode());

        $expectedCode = Base64UrlSafe::encodeUnpadded(
            Json::encode(
                [
                    'v' => OAuthServer::TOKEN_VERSION,
                    'type' => 'authorization_code',
                    'auth_key' => 'random_1',
                    'user_id' => 'foo',
                    'client_id' => 'code-client',
                    'scope' => 'foo',
                    'redirect_uri' => 'http://example.org/code-cb',
                    'code_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
                    'expires_at' => '2016-01-01T00:05:00+00:00',
                ]
            )
        );

        $this->assertSame(
            [
                'Location' => \sprintf('http://example.org/code-cb?code=%s&state=12345', $expectedCode),
                'Content-Type' => 'text/html; charset=utf-8',
            ],
            $authorizeResponse->getHeaders()
        );
    }

    /**
     * @return void
     */
    public function testAuthorizeTokenPostRedirectUriWithQuery()
    {
        $authorizeResponse = $this->server->postAuthorize(
            [
                'client_id' => 'code-client-query-redirect',
                'redirect_uri' => 'http://example.org/code-cb?keep=this',
                'response_type' => 'code',
                'scope' => 'config',
                'state' => '12345',
                'code_challenge_method' => 'S256',
                'code_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            ],
            [
                'approve' => 'yes',
            ],
            'foo'
        );
        $this->assertSame(302, $authorizeResponse->getStatusCode());

        $expectedCode = Base64UrlSafe::encodeUnpadded(
            Json::encode(
                [
                    'v' => OAuthServer::TOKEN_VERSION,
                    'type' => 'authorization_code',
                    'auth_key' => 'random_1',
                    'user_id' => 'foo',
                    'client_id' => 'code-client-query-redirect',
                    'scope' => 'config',
                    'redirect_uri' => 'http://example.org/code-cb?keep=this',
                    'code_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
                    'expires_at' => '2016-01-01T00:05:00+00:00',
                ]
            )
        );

        $this->assertSame(
            [
                'Location' => \sprintf('http://example.org/code-cb?keep=this&code=%s&state=12345', $expectedCode),
                'Content-Type' => 'text/html; charset=utf-8',
            ],
            $authorizeResponse->getHeaders()
        );
    }

    /**
     * @return void
     */
    public function testPostToken()
    {
        $providedCode = Base64UrlSafe::encodeUnpadded(
            Json::encode(
                [
                    'v' => OAuthServer::TOKEN_VERSION,
                    'type' => 'authorization_code',
                    'auth_key' => 'random_1',
                    'user_id' => 'foo',
                    'client_id' => 'code-client',
                    'scope' => 'config',
                    'redirect_uri' => 'http://example.org/code-cb',
                    'code_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
                    'expires_at' => '2016-01-01T00:05:00+00:00',
                ]
            )
        );

        $tokenResponse = $this->server->postToken(
            [
                'grant_type' => 'authorization_code',
                'code' => $providedCode,
                'redirect_uri' => 'http://example.org/code-cb',
                'client_id' => 'code-client',
                'code_verifier' => 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
            ],
            null,
            null
        );
        $this->assertSame(200, $tokenResponse->getStatusCode());
        $this->assertSame(
            [
                'Cache-Control' => 'no-store',
                'Pragma' => 'no-cache',
                'Content-Type' => 'application/json',
            ],
            $tokenResponse->getHeaders()
        );

        $expectedAccessToken = Base64UrlSafe::encodeUnpadded(
            Json::encode(
                [
                    'v' => OAuthServer::TOKEN_VERSION,
                    'type' => 'access_token',
                    'auth_key' => 'random_1',
                    'user_id' => 'foo',
                    'client_id' => 'code-client',
                    'scope' => 'config',
                    'expires_at' => '2016-01-01T01:00:00+00:00',
                ]
            )
        );
        $expectedRefreshToken = Base64UrlSafe::encodeUnpadded(
            Json::encode(
                [
                    'v' => OAuthServer::TOKEN_VERSION,
                    'type' => 'refresh_token',
                    'auth_key' => 'random_1',
                    'user_id' => 'foo',
                    'client_id' => 'code-client',
                    'scope' => 'config',
                ]
            )
        );

        $this->assertSame(
            [
                'access_token' => $expectedAccessToken,
                'refresh_token' => $expectedRefreshToken,
                'token_type' => 'bearer',
                'expires_in' => 3600,
            ],
            \json_decode($tokenResponse->getBody(), true)
        );
    }

    /**
     * @return void
     */
    public function testPostTokenSecret()
    {
        $providedCode = Base64UrlSafe::encodeUnpadded(
            Json::encode(
                [
                    'v' => OAuthServer::TOKEN_VERSION,
                    'type' => 'authorization_code',
                    'auth_key' => 'random_1',
                    'user_id' => 'foo',
                    'client_id' => 'code-client-secret',
                    'scope' => 'config',
                    'redirect_uri' => 'http://example.org/code-cb',
                    'code_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
                    'expires_at' => '2016-01-01T00:05:00+00:00',
                ]
            )
        );

        $tokenResponse = $this->server->postToken(
            [
                'grant_type' => 'authorization_code',
                'code' => $providedCode,
                'redirect_uri' => 'http://example.org/code-cb',
                'client_id' => 'code-client-secret',
                'code_verifier' => 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
            ],
            'code-client-secret',
            '123456'
        );

        $expectedAccessToken = Base64UrlSafe::encodeUnpadded(
            Json::encode(
                [
                    'v' => OAuthServer::TOKEN_VERSION,
                    'type' => 'access_token',
                    'auth_key' => 'random_1',
                    'user_id' => 'foo',
                    'client_id' => 'code-client-secret',
                    'scope' => 'config',
                    'expires_at' => '2016-01-01T01:00:00+00:00',
                ]
            )
        );
        $expectedRefreshToken = Base64UrlSafe::encodeUnpadded(
            Json::encode(
                [
                    'v' => OAuthServer::TOKEN_VERSION,
                    'type' => 'refresh_token',
                    'auth_key' => 'random_1',
                    'user_id' => 'foo',
                    'client_id' => 'code-client-secret',
                    'scope' => 'config',
                ]
            )
        );

        $this->assertSame(
            [
                'access_token' => $expectedAccessToken,
                'refresh_token' => $expectedRefreshToken,
                'token_type' => 'bearer',
                'expires_in' => 3600,
            ],
            \json_decode($tokenResponse->getBody(), true)
        );
    }

    /**
     * @return void
     */
    public function testPostTokenMissingCodeVerifier()
    {
        $providedCode = Base64UrlSafe::encodeUnpadded(
            Json::encode(
                [
                    'v' => OAuthServer::TOKEN_VERSION,
                    'type' => 'authorization_code',
                    'auth_key' => 'random_1',
                    'user_id' => 'foo',
                    'client_id' => 'code-client',
                    'scope' => 'config',
                    'redirect_uri' => 'http://example.org/code-cb',
                    'code_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
                    'expires_at' => '2016-01-01T00:05:00+00:00',
                ]
            )
        );

        try {
            $this->storage->storeAuthorization('foo', 'code-client', 'config', 'random_1');
            $this->server->postToken(
                [
                    'grant_type' => 'authorization_code',
                    'code' => $providedCode,
                    'redirect_uri' => 'http://example.org/code-cb',
                    'client_id' => 'code-client',
                ],
                null,
                null
            );
            $this->fail();
        } catch (InvalidRequestException $e) {
            $this->assertSame('missing "code_verifier" parameter', $e->getDescription());
        }
    }

    /**
     * @return void
     */
    public function testBrokenPostToken()
    {
        try {
            $this->server->postToken(
                [
                ],
                null,
                null
            );
            $this->fail();
        } catch (InvalidRequestException $e) {
            $this->assertSame('missing "grant_type" parameter', $e->getDescription());
        }
    }

    /**
     * @return void
     */
    public function testPostTokenSecretInvalid()
    {
        try {
            $this->server->postToken(
                [
                    'grant_type' => 'authorization_code',
                    'code' => 'DEF.abcdefgh',
                    'redirect_uri' => 'http://example.org/code-cb',
                    'client_id' => 'code-client-secret',
                    'code_verifier' => 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
                ],
                'code-client-secret',
                '654321'
            );
            $this->fail();
        } catch (InvalidClientException $e) {
            $this->assertSame('invalid credentials (invalid authenticating pass)', $e->getDescription());
        }
    }

    /**
     * @return void
     */
    public function testPostReuseCode()
    {
        try {
            $this->storage->storeAuthorization('foo', 'code-client', 'config', 'random_1');

            $providedCode = Base64UrlSafe::encodeUnpadded(
                Json::encode(
                    [
                        'v' => OAuthServer::TOKEN_VERSION,
                        'type' => 'authorization_code',
                        'auth_key' => 'random_1',
                        'user_id' => 'foo',
                        'client_id' => 'code-client',
                        'scope' => 'config',
                        'redirect_uri' => 'http://example.org/code-cb',
                        'code_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
                        'expires_at' => '2016-01-01T00:05:00+00:00',
                    ]
                )
            );

            $this->server->postToken(
                [
                    'grant_type' => 'authorization_code',
                    'code' => $providedCode,
                    'redirect_uri' => 'http://example.org/code-cb',
                    'client_id' => 'code-client',
                    'code_verifier' => 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
                ],
                null,
                null
            );
            $this->fail();
        } catch (InvalidGrantException $e) {
            $this->assertSame('"authorization_code" was used before', $e->getDescription());
        }
    }

    /**
     * @return void
     */
    public function testExpiredCode()
    {
        try {
            $providedCode = Base64UrlSafe::encodeUnpadded(
                Json::encode(
                    [
                        'v' => OAuthServer::TOKEN_VERSION,
                        'type' => 'authorization_code',
                        'auth_key' => 'random_1',
                        'user_id' => 'foo',
                        'client_id' => 'code-client',
                        'scope' => 'config',
                        'redirect_uri' => 'http://example.org/code-cb',
                        'code_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
                        'expires_at' => '2015-01-01T00:05:00+00:00',
                    ]
                )
            );

            $this->server->postToken(
                [
                    'grant_type' => 'authorization_code',
                    'code' => $providedCode,
                    'redirect_uri' => 'http://example.org/code-cb',
                    'client_id' => 'code-client',
                    'code_verifier' => 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
                ],
                null,
                null
            );
            $this->fail();
        } catch (InvalidGrantException $e) {
            $this->assertSame('"authorization_code" expired', $e->getDescription());
        }
    }

    /**
     * @return void
     */
    public function testAccessTokenAsCode()
    {
        try {
            $this->storage->storeAuthorization('foo', 'code-client', 'config', 'random_1');

            $providedCode = Base64UrlSafe::encodeUnpadded(
                Json::encode(
                    [
                        'v' => OAuthServer::TOKEN_VERSION,
                        'type' => 'access_token',
                        'auth_key' => 'random_1',
                        'user_id' => 'foo',
                        'client_id' => 'code-client',
                        'scope' => 'config',
                        'expires_at' => '2016-01-01T01:00:00+00:00',
                    ]
                )
            );

            $this->server->postToken(
                [
                    'grant_type' => 'authorization_code',
                    'code' => $providedCode,
                    'redirect_uri' => 'http://example.org/code-cb',
                    'client_id' => 'code-client',
                    'code_verifier' => 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
                ],
                null,
                null
            );
            $this->fail();
        } catch (InvalidGrantException $e) {
            $this->assertSame('expected "authorization_code", got "access_token"', $e->getDescription());
        }
    }

    /**
     * @return void
     */
    public function testRefreshTokenWithoutExplicitScope()
    {
        $this->storage->storeAuthorization('foo', 'code-client-secret', 'config', 'random_1');

        $providedRefreshToken = Base64UrlSafe::encodeUnpadded(
            Json::encode(
                [
                    'v' => OAuthServer::TOKEN_VERSION,
                    'type' => 'refresh_token',
                    'auth_key' => 'random_1',
                    'user_id' => 'foo',
                    'client_id' => 'code-client-secret',
                    'scope' => 'config',
                ]
            )
        );

        $tokenResponse = $this->server->postToken(
            [
                'grant_type' => 'refresh_token',
                'refresh_token' => $providedRefreshToken,
            ],
            'code-client-secret',
            '123456'
        );

        $expectedAccessToken = Base64UrlSafe::encodeUnpadded(
            Json::encode(
                [
                    'v' => OAuthServer::TOKEN_VERSION,
                    'type' => 'access_token',
                    'auth_key' => 'random_1',
                    'user_id' => 'foo',
                    'client_id' => 'code-client-secret',
                    'scope' => 'config',
                    'expires_at' => '2016-01-01T01:00:00+00:00',
                ]
            )
        );

        $this->assertSame(
            [
                'access_token' => $expectedAccessToken,
                'token_type' => 'bearer',
                'expires_in' => 3600,
            ],
            \json_decode($tokenResponse->getBody(), true)
        );
    }

    /**
     * @return void
     */
    public function testLoopbackClient()
    {
        $this->assertSame(
            [
                'client_id' => 'loopback',
                'display_name' => 'Loopback Client',
                'scope' => 'config',
                'redirect_uri' => 'http://127.0.0.1:12345/cb',
            ],
            $this->server->getAuthorize(
                [
                    'client_id' => 'loopback',
                    'redirect_uri' => 'http://127.0.0.1:12345/cb',
                    'response_type' => 'code',
                    'scope' => 'config',
                    'state' => '12345',
                    'code_challenge_method' => 'S256',
                    'code_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
                ]
            )
        );
    }

    /**
     * @return void
     */
    public function testDeleteAuthorization()
    {
        $this->storage->storeAuthorization('foo', 'code-client', 'config', 'random_1');
        $this->storage->storeAuthorization('foo', 'code-client', 'config', 'random_2');
        $this->storage->storeAuthorization('foo', 'code-client', 'config', 'random_3');
        $this->storage->storeAuthorization('foo', 'code-client', 'config', 'random_4');
        $this->assertSame(4, \count($this->storage->getAuthorizations('foo')));
        $this->storage->deleteAuthorization('random_1');
        $this->assertSame(3, \count($this->storage->getAuthorizations('foo')));
    }
}
