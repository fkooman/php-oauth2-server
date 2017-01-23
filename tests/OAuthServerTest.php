<?php
/**
 *  Copyright (C) 2016 François Kooman <fkooman@tuxed.net>.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as
 *  published by the Free Software Foundation, either version 3 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

namespace fkooman\OAuth\Server;

use DateTime;
use fkooman\OAuth\Server\Exception\TokenException;
use PDO;
use PHPUnit_Framework_TestCase;

class OAuthServerTest extends PHPUnit_Framework_TestCase
{
    /** @var OAuthServer */
    private $server;

    public function setUp()
    {
        $random = $this->getMockBuilder('\fkooman\OAuth\Server\RandomInterface')->getMock();
        $random->method('get')->will($this->onConsecutiveCalls('random_1', 'random_2'));

        $oauthClients = [
            'token-client' => [
                'redirect_uri' => 'http://example.org/token-cb',
                'response_type' => 'token',
                'display_name' => 'Token Client',
            ],
            'code-client' => [
                'redirect_uri' => 'http://example.org/code-cb',
                'response_type' => 'code',
                'display_name' => 'Code Client',
            ],
            'code-client-secret' => [
                'redirect_uri' => 'http://example.org/code-cb',
                'response_type' => 'code',
                'display_name' => 'Code Client',
                'client_secret' => '123456',
            ],
        ];

        $getClientInfo = function ($clientId) use ($oauthClients) {
            if (!array_key_exists($clientId, $oauthClients)) {
                return false;
            }

            return $oauthClients[$clientId];
        };

        $tokenStorage = new TokenStorage(new PDO('sqlite::memory:'));
        $tokenStorage->init();

        $tokenStorage->storeCode('foo', 'XYZ', 'abcdefgh', 'code-client', 'config', 'http://example.org/code-cb', new DateTime('2016-01-01'), 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
        $tokenStorage->storeCode('foo', 'DEF', 'abcdefgh', 'code-client-secret', 'config', 'http://example.org/code-cb', new DateTime('2016-01-01'), 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');

        $this->server = new OAuthServer(
            $tokenStorage,
            $random,
            new DateTime('2016-01-01'),
            $getClientInfo
        );
    }

    public function testAuthorizeToken()
    {
        $this->assertSame(
            [
                'client_id' => 'token-client',
                'display_name' => 'Token Client',
                'scope' => 'config',
                'redirect_uri' => 'http://example.org/token-cb',
            ],
            $this->server->getAuthorize(
                [
                    'client_id' => 'token-client',
                    'redirect_uri' => 'http://example.org/token-cb',
                    'response_type' => 'token',
                    'scope' => 'config',
                    'state' => '12345',
                ],
                'foo'
            )
        );
    }

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
                ],
                'foo'
            )
        );
    }

    public function testAuthorizeTokenPost()
    {
        $this->assertSame(
            'http://example.org/token-cb#access_token=cmFuZG9tXzE.cmFuZG9tXzI&state=12345&expires_in=3600',
            $this->server->postAuthorize(
                [
                    'client_id' => 'token-client',
                    'redirect_uri' => 'http://example.org/token-cb',
                    'response_type' => 'token',
                    'scope' => 'config',
                    'state' => '12345',
                ],
                [
                    'approve' => 'yes',
                ],
                'foo'
            )
        );
    }

    public function testAuthorizeCodePost()
    {
        $this->assertSame(
            'http://example.org/code-cb?code=cmFuZG9tXzE.cmFuZG9tXzI&state=12345',
            $this->server->postAuthorize(
                [
                    'client_id' => 'code-client',
                    'redirect_uri' => 'http://example.org/code-cb',
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
            )
        );
    }

    public function testBrokenPostToken()
    {
        try {
            $this->server->postToken(
                [
                ],
                null,
                null
            );
            $this->assertFalse(true);
        } catch (TokenException $e) {
            $this->assertEquals(400, $e->getResponse()->getStatusCode());
            $this->assertEquals(
                [
                    'error' => 'invalid_request',
                    'error_description' => 'missing "grant_type" parameter',
                ],
                $e->getResponse()->getArrayBody()
            );
            $this->assertEquals(
                [
                    'Content-Type' => 'application/json',
                    'Cache-Control' => 'no-store',
                    'Pragma' => 'no-cache',
                ],
                $e->getResponse()->getHeaders()
            );
        }
    }

    public function testPostToken()
    {
        $tokenResponse = $this->server->postToken(
            [
                'grant_type' => 'authorization_code',
                'code' => 'XYZ.abcdefgh',
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
                'Content-Type' => 'application/json',
                'Cache-Control' => 'no-store',
                'Pragma' => 'no-cache',
            ],
            $tokenResponse->getHeaders()
        );
        $this->assertSame(
            [
                'access_token' => 'XYZ.cmFuZG9tXzE',
                'token_type' => 'bearer',
                'expires_in' => 3600,
            ],
            $tokenResponse->getArrayBody()
        );
    }

    public function testPostTokenSecret()
    {
        $tokenResponse = $this->server->postToken(
            [
                'grant_type' => 'authorization_code',
                'code' => 'DEF.abcdefgh',
                'redirect_uri' => 'http://example.org/code-cb',
                'client_id' => 'code-client-secret',
                'code_verifier' => 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
            ],
            'code-client-secret',
            '123456'
        );

        $this->assertSame(200, $tokenResponse->getStatusCode());
        $this->assertSame(
            [
                'Content-Type' => 'application/json',
                'Cache-Control' => 'no-store',
                'Pragma' => 'no-cache',
            ],
            $tokenResponse->getHeaders()
        );
        $this->assertSame(
            [
                'access_token' => 'DEF.cmFuZG9tXzE',
                'token_type' => 'bearer',
                'expires_in' => 3600,
            ],
            $tokenResponse->getArrayBody()
        );
    }

    public function testPostTokenSecretInvalid()
    {
        try {
            $tokenResponse = $this->server->postToken(
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
            $this->assertTrue(false);
        } catch (TokenException $e) {
            $this->assertEquals(401, $e->getResponse()->getStatusCode());
            $this->assertEquals(
                [
                    'error' => 'invalid_client',
                    'error_description' => 'invalid "client_secret"',
                ],
                $e->getResponse()->getArrayBody()
            );
            $this->assertEquals(
                [
                    'Content-Type' => 'application/json',
                    'Cache-Control' => 'no-store',
                    'Pragma' => 'no-cache',
                    'WWW-Authenticate' => 'Bearer realm="OAuth",error=invalid_client,error_description=invalid "client_secret"',
                ],
                $e->getResponse()->getHeaders()
            );
        }
    }

    public function testPostReuseCode()
    {
    }

    public function testExpiredCode()
    {
    }

    /**
     * Test getting access_token when one was already issued to same client
     * with same scope.
     */
    public function testAuthorizeTokenExistingAccessToken()
    {
    }
}
