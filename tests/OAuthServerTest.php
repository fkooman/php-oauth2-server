<?php

/**
 * Copyright (c) 2017 François Kooman <fkooman@tuxed.net>.
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
use fkooman\OAuth\Server\ClientInfo;
use fkooman\OAuth\Server\OAuthServer;
use fkooman\OAuth\Server\Storage;
use PDO;
use PHPUnit\Framework\TestCase;

class OAuthServerTest extends TestCase
{
    /** @var \fkooman\OAuth\Server\Storage */
    private $storage;

    /** @var \fkooman\OAuth\Server\OAuthServer */
    private $server;

    public function setUp()
    {
        $oauthClients = [
            'code-client' => [
                'redirect_uri' => 'http://example.org/code-cb',
                'response_type' => 'code',
                'display_name' => 'Code Client',
            ],
            'code-client-query-redirect' => [
                'response_type' => 'code',
                'redirect_uri' => 'http://example.org/code-cb?keep=this',
                'display_name' => 'Code Client',
            ],
            'code-client-secret' => [
                'response_type' => 'code',
                'redirect_uri' => 'http://example.org/code-cb',
                'display_name' => 'Code Client',
                'client_secret' => '123456',
            ],
            'loopback' => [
                'response_type' => 'code',
                'redirect_uri' => 'http://127.0.0.1:{PORT}/cb',
                'display_name' => 'Loopback Client',
            ],
        ];

        $getClientInfo = function ($clientId) use ($oauthClients) {
            if (!array_key_exists($clientId, $oauthClients)) {
                return false;
            }

            return new ClientInfo($oauthClients[$clientId]);
        };

        $this->storage = new Storage(new PDO('sqlite::memory:'));
        $this->storage->init();

        $keyPair = '2y5vJlGqpjTzwr3Ym3UqNwJuI1BKeLs53fc6Zf84kbYcP2/6Ar7zgiPS6BL4bvCaWN4uatYfuP7Dj/QvdctqJRw/b/oCvvOCI9LoEvhu8JpY3i5q1h+4/sOP9C91y2ol';

        $this->server = new OAuthServer($this->storage, $getClientInfo, $keyPair);
        $this->server->setDateTime(new DateTime('2016-01-01'));
        $this->server->setRandom(new TestRandom());
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
                ]
            )
        );
    }

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
        $this->assertSame(
            [
                'Location' => 'http://example.org/code-cb?code=eAK58VRxVi1FHxAG6dhSzao2Ty7wKlDHwuFF5G1ilVIdZP9PW6IwpFUb9VsNcFvjgS35wAqtMnky16buhyYxB3sidHlwZSI6ImF1dGhvcml6YXRpb25fY29kZSIsImF1dGhfa2V5IjoicmFuZG9tXzEiLCJ1c2VyX2lkIjoiZm9vIiwiY2xpZW50X2lkIjoiY29kZS1jbGllbnQiLCJzY29wZSI6ImZvbyIsInJlZGlyZWN0X3VyaSI6Imh0dHA6XC9cL2V4YW1wbGUub3JnXC9jb2RlLWNiIiwiY29kZV9jaGFsbGVuZ2UiOiJFOU1lbGhvYTJPd3ZGckVNVEpndUNIYW9lSzF0OFVSV2J1R0pTc3R3LWNNIiwiZXhwaXJlc19hdCI6IjIwMTYtMDEtMDEgMDA6MDU6MDAifQ%3D%3D&state=12345',
                'Content-Type' => 'text/html; charset=utf-8',
            ],
            $authorizeResponse->getHeaders()
        );
    }

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
        $this->assertSame(
            [
                'Location' => 'http://example.org/code-cb?keep=this&code=PxOQ%2FysqZ65ozJ8aEsMaQfBuK0jJqyr2UPqvWCiUxUWKPz5C009%2Bv3ShcgGwa93VNogtY1%2FSENKlKmCzHgdMBHsidHlwZSI6ImF1dGhvcml6YXRpb25fY29kZSIsImF1dGhfa2V5IjoicmFuZG9tXzEiLCJ1c2VyX2lkIjoiZm9vIiwiY2xpZW50X2lkIjoiY29kZS1jbGllbnQtcXVlcnktcmVkaXJlY3QiLCJzY29wZSI6ImNvbmZpZyIsInJlZGlyZWN0X3VyaSI6Imh0dHA6XC9cL2V4YW1wbGUub3JnXC9jb2RlLWNiP2tlZXA9dGhpcyIsImNvZGVfY2hhbGxlbmdlIjoiRTlNZWxob2EyT3d2RnJFTVRKZ3VDSGFvZUsxdDhVUldidUdKU3N0dy1jTSIsImV4cGlyZXNfYXQiOiIyMDE2LTAxLTAxIDAwOjA1OjAwIn0%3D&state=12345',
                'Content-Type' => 'text/html; charset=utf-8',
            ],
            $authorizeResponse->getHeaders()
        );
    }

    public function testPostToken()
    {
        $this->storage->storeAuthorization('foo', 'code-client', 'config', 'random_1');
        $tokenResponse = $this->server->postToken(
            [
                'grant_type' => 'authorization_code',
                'code' => 'nmVljssjTwA29QjWrzieuAQjwR0yJo6DodWaTAa72t03WWyGDA8ajTdUy0Dzklrzx4kUjkL7MX/BaE2PUuykBHsidHlwZSI6ImF1dGhvcml6YXRpb25fY29kZSIsImF1dGhfa2V5IjoicmFuZG9tXzEiLCJ1c2VyX2lkIjoiZm9vIiwiY2xpZW50X2lkIjoiY29kZS1jbGllbnQiLCJzY29wZSI6ImNvbmZpZyIsInJlZGlyZWN0X3VyaSI6Imh0dHA6XC9cL2V4YW1wbGUub3JnXC9jb2RlLWNiIiwiY29kZV9jaGFsbGVuZ2UiOiJFOU1lbGhvYTJPd3ZGckVNVEpndUNIYW9lSzF0OFVSV2J1R0pTc3R3LWNNIiwiZXhwaXJlc19hdCI6IjIwMTYtMDEtMDEgMDA6MDU6MDAifQ==',
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
        $this->assertSame(
            [
                'access_token' => 'znwcwk0WpP1y0qrUSd/J6KToSlXdceGBaliVLhYYjRESQoVZI1aZTX9cRfBfIpOBnMcyTF3Izs9H8918OwiqBHsidHlwZSI6ImFjY2Vzc190b2tlbiIsImF1dGhfa2V5IjoicmFuZG9tXzEiLCJ1c2VyX2lkIjoiZm9vIiwiY2xpZW50X2lkIjoiY29kZS1jbGllbnQiLCJzY29wZSI6ImNvbmZpZyIsImV4cGlyZXNfYXQiOiIyMDE2LTAxLTAxIDAxOjAwOjAwIn0=',
                'refresh_token' => 'wi5vLrEtTVmTFfI+lLCfVVg3b6punZLQs6+N/8Q67ybHLEqdDzxXYjD3FePW3KmMW0NhVqMOFge52h8U30lQC3sidHlwZSI6InJlZnJlc2hfdG9rZW4iLCJhdXRoX2tleSI6InJhbmRvbV8xIiwidXNlcl9pZCI6ImZvbyIsImNsaWVudF9pZCI6ImNvZGUtY2xpZW50Iiwic2NvcGUiOiJjb25maWcifQ==',
                'token_type' => 'bearer',
                'expires_in' => 3600,
            ],
            json_decode($tokenResponse->getBody(), true)
        );
    }

    public function testPostTokenSecret()
    {
        $this->storage->storeAuthorization('foo', 'code-client-secret', 'config', 'random_1');
        $tokenResponse = $this->server->postToken(
            [
                'grant_type' => 'authorization_code',
                'code' => 'VBDHzOyeWDZuMsp0s6JUBGmncqLh4YpvjlefiRFzyqU8nftgoGr9uKn2GY36Y/WxAh1sZ6kX/brWj8OohNpZBHsidHlwZSI6ImF1dGhvcml6YXRpb25fY29kZSIsImF1dGhfa2V5IjoicmFuZG9tXzEiLCJ1c2VyX2lkIjoiZm9vIiwiY2xpZW50X2lkIjoiY29kZS1jbGllbnQtc2VjcmV0Iiwic2NvcGUiOiJjb25maWciLCJyZWRpcmVjdF91cmkiOiJodHRwOlwvXC9leGFtcGxlLm9yZ1wvY29kZS1jYiIsImNvZGVfY2hhbGxlbmdlIjoiRTlNZWxob2EyT3d2RnJFTVRKZ3VDSGFvZUsxdDhVUldidUdKU3N0dy1jTSIsImV4cGlyZXNfYXQiOiIyMDE2LTAxLTAxIDAwOjA1OjAwIn0=',
                'redirect_uri' => 'http://example.org/code-cb',
                'client_id' => 'code-client-secret',
            ],
            'code-client-secret',
            '123456'
        );
        $this->assertSame(
            [
                'access_token' => 'A5G2q7GegYUXU4zP6PwnMqMRbTKTFuq78KxEUxZx20iogM/5Wiv2LnoKWk+3T7VJoc7fdxeDJG9HQnKns7ynCXsidHlwZSI6ImFjY2Vzc190b2tlbiIsImF1dGhfa2V5IjoicmFuZG9tXzEiLCJ1c2VyX2lkIjoiZm9vIiwiY2xpZW50X2lkIjoiY29kZS1jbGllbnQtc2VjcmV0Iiwic2NvcGUiOiJjb25maWciLCJleHBpcmVzX2F0IjoiMjAxNi0wMS0wMSAwMTowMDowMCJ9',
                'refresh_token' => 'uMCJapjl8ZBWIeid8fSgA6urOwNZMGw7GBHz2lP1g9BrIM1Epkui0NiDQ/Un4dq8h7HoCGyhUBJ326zdIcJ2AnsidHlwZSI6InJlZnJlc2hfdG9rZW4iLCJhdXRoX2tleSI6InJhbmRvbV8xIiwidXNlcl9pZCI6ImZvbyIsImNsaWVudF9pZCI6ImNvZGUtY2xpZW50LXNlY3JldCIsInNjb3BlIjoiY29uZmlnIn0=',
                'token_type' => 'bearer',
                'expires_in' => 3600,
            ],
            json_decode($tokenResponse->getBody(), true)
        );
    }

    public function testPostTokenMissingCodeVerifierPublicClient()
    {
    }

    /**
     * @expectedException \fkooman\OAuth\Server\Exception\OAuthException
     * @expectedExceptionMessage invalid_request
     */
    public function testBrokenPostToken()
    {
        $this->server->postToken(
            [
            ],
            null,
            null
        );
    }

    /**
     * @expectedException \fkooman\OAuth\Server\Exception\OAuthException
     * @expectedExceptionMessage invalid_client
     */
    public function testPostTokenSecretInvalid()
    {
        $this->server->postToken(
            [
                'grant_type' => 'authorization_code',
                'code' => 'DEF.abcdefgh',
                'redirect_uri' => 'http://example.org/code-cb',
                'client_id' => 'code-client-secret',
            ],
            'code-client-secret',
            '654321'
        );
    }

    /**
     * @expectedException \fkooman\OAuth\Server\Exception\OAuthException
     * @expectedExceptionMessage invalid_grant
     */
    public function testPostReuseCode()
    {
        $this->storage->storeAuthorization('foo', 'code-client', 'config', 'random_1');
        $this->storage->logAuthKey('random_1');
        $this->server->postToken(
            [
                'grant_type' => 'authorization_code',
                'code' => 'nmVljssjTwA29QjWrzieuAQjwR0yJo6DodWaTAa72t03WWyGDA8ajTdUy0Dzklrzx4kUjkL7MX/BaE2PUuykBHsidHlwZSI6ImF1dGhvcml6YXRpb25fY29kZSIsImF1dGhfa2V5IjoicmFuZG9tXzEiLCJ1c2VyX2lkIjoiZm9vIiwiY2xpZW50X2lkIjoiY29kZS1jbGllbnQiLCJzY29wZSI6ImNvbmZpZyIsInJlZGlyZWN0X3VyaSI6Imh0dHA6XC9cL2V4YW1wbGUub3JnXC9jb2RlLWNiIiwiY29kZV9jaGFsbGVuZ2UiOiJFOU1lbGhvYTJPd3ZGckVNVEpndUNIYW9lSzF0OFVSV2J1R0pTc3R3LWNNIiwiZXhwaXJlc19hdCI6IjIwMTYtMDEtMDEgMDA6MDU6MDAifQ==',
                'redirect_uri' => 'http://example.org/code-cb',
                'client_id' => 'code-client',
                'code_verifier' => 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
            ],
            null,
            null
        );
    }

    /**
     * @expectedException \fkooman\OAuth\Server\Exception\OAuthException
     * @expectedExceptionMessage invalid_grant
     */
    public function testExpiredCode()
    {
        $this->server->setDateTime(new DateTime('2017-01-01'));
        $this->server->postToken(
            [
                'grant_type' => 'authorization_code',
                'code' => 'nmVljssjTwA29QjWrzieuAQjwR0yJo6DodWaTAa72t03WWyGDA8ajTdUy0Dzklrzx4kUjkL7MX/BaE2PUuykBHsidHlwZSI6ImF1dGhvcml6YXRpb25fY29kZSIsImF1dGhfa2V5IjoicmFuZG9tXzEiLCJ1c2VyX2lkIjoiZm9vIiwiY2xpZW50X2lkIjoiY29kZS1jbGllbnQiLCJzY29wZSI6ImNvbmZpZyIsInJlZGlyZWN0X3VyaSI6Imh0dHA6XC9cL2V4YW1wbGUub3JnXC9jb2RlLWNiIiwiY29kZV9jaGFsbGVuZ2UiOiJFOU1lbGhvYTJPd3ZGckVNVEpndUNIYW9lSzF0OFVSV2J1R0pTc3R3LWNNIiwiZXhwaXJlc19hdCI6IjIwMTYtMDEtMDEgMDA6MDU6MDAifQ==',
                'redirect_uri' => 'http://example.org/code-cb',
                'client_id' => 'code-client',
                'code_verifier' => 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
            ],
            null,
            null
        );
    }

    public function testGetPublicKey()
    {
        $this->assertSame('HD9v+gK+84Ij0ugS+G7wmljeLmrWH7j+w4/0L3XLaiU=', $this->server->getPublicKey());
    }

    public function testAccessTokenAsCode()
    {
    }

    public function testCodeAsAccessToken()
    {
    }

    public function testRefreshToken()
    {
        // the authorization MUST exist for the refresh token to work
        $this->storage->storeAuthorization('foo', 'code-client', 'config', 'random_1');
        $tokenResponse = $this->server->postToken(
            [
                'grant_type' => 'refresh_token',
                'refresh_token' => 'wi5vLrEtTVmTFfI+lLCfVVg3b6punZLQs6+N/8Q67ybHLEqdDzxXYjD3FePW3KmMW0NhVqMOFge52h8U30lQC3sidHlwZSI6InJlZnJlc2hfdG9rZW4iLCJhdXRoX2tleSI6InJhbmRvbV8xIiwidXNlcl9pZCI6ImZvbyIsImNsaWVudF9pZCI6ImNvZGUtY2xpZW50Iiwic2NvcGUiOiJjb25maWcifQ==',
                'scope' => 'config',
            ],
            null,
            null
        );
        $this->assertSame(
            [
                'access_token' => 'znwcwk0WpP1y0qrUSd/J6KToSlXdceGBaliVLhYYjRESQoVZI1aZTX9cRfBfIpOBnMcyTF3Izs9H8918OwiqBHsidHlwZSI6ImFjY2Vzc190b2tlbiIsImF1dGhfa2V5IjoicmFuZG9tXzEiLCJ1c2VyX2lkIjoiZm9vIiwiY2xpZW50X2lkIjoiY29kZS1jbGllbnQiLCJzY29wZSI6ImNvbmZpZyIsImV4cGlyZXNfYXQiOiIyMDE2LTAxLTAxIDAxOjAwOjAwIn0=',
                'token_type' => 'bearer',
                'expires_in' => 3600,
            ],
            json_decode($tokenResponse->getBody(), true)
        );
    }

    public function testLoopbackClient()
    {
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
        );
    }

    public function testDeleteAuthorization()
    {
        $this->storage->storeAuthorization('foo', 'code-client', 'config', 'random_1');
        $this->storage->storeAuthorization('foo', 'code-client', 'config', 'random_2');
        $this->storage->storeAuthorization('foo', 'code-client', 'config', 'random_3');
        $this->storage->storeAuthorization('foo', 'code-client', 'config', 'random_4');
        $this->assertSame(1, count($this->storage->getAuthorizations('foo')));
        $this->storage->deleteAuthorization('foo', 'code-client', 'config');
        $this->assertSame(0, count($this->storage->getAuthorizations('foo')));
    }
}
