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
use PDO;
use PHPUnit_Framework_TestCase;

class OAuthServerTest extends PHPUnit_Framework_TestCase
{
    /** @var Storage */
    private $storage;

    /** @var callable */
    private $getClientInfo;

    /** @var string */
    private $keyPair;

    /** @var Random */
    private $random;

    /** @var \DateTime */
    private $dateTime;

    public function setUp()
    {
        $this->random = $this->getMockBuilder('\fkooman\OAuth\Server\RandomInterface')->getMock();
        $this->random->method('get')->will($this->onConsecutiveCalls('random_1', 'random_2'));

        $oauthClients = [
            'code-client' => [
                'redirect_uri' => 'http://example.org/code-cb',
                'display_name' => 'Code Client',
            ],
            'code-client-query-redirect' => [
                'redirect_uri' => 'http://example.org/code-cb?keep=this',
                'display_name' => 'Code Client',
            ],
            'code-client-secret' => [
                'redirect_uri' => 'http://example.org/code-cb',
                'display_name' => 'Code Client',
                'client_secret' => '123456',
            ],
        ];

        $this->getClientInfo = function ($clientId) use ($oauthClients) {
            if (!array_key_exists($clientId, $oauthClients)) {
                return false;
            }

            return $oauthClients[$clientId];
        };

        $this->storage = new Storage(new PDO('sqlite::memory:'));
        $this->storage->init();

        $this->keyPair = '2y5vJlGqpjTzwr3Ym3UqNwJuI1BKeLs53fc6Zf84kbYcP2/6Ar7zgiPS6BL4bvCaWN4uatYfuP7Dj/QvdctqJRw/b/oCvvOCI9LoEvhu8JpY3i5q1h+4/sOP9C91y2ol';

        $this->dateTime = new DateTime('2016-01-01');
    }

    public function testAuthorizeCode()
    {
        $server = new OAuthServer($this->getClientInfo, $this->keyPair, $this->storage, $this->random, $this->dateTime);
        $this->assertSame(
            [
                'client_id' => 'code-client',
                'display_name' => 'Code Client',
                'scope' => 'config',
                'redirect_uri' => 'http://example.org/code-cb',
            ],
            $server->getAuthorize(
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
        $server = new OAuthServer($this->getClientInfo, $this->keyPair, $this->storage, $this->random, $this->dateTime);
        $this->assertSame(
            'http://example.org/code-cb?code=eAK58VRxVi1FHxAG6dhSzao2Ty7wKlDHwuFF5G1ilVIdZP9PW6IwpFUb9VsNcFvjgS35wAqtMnky16buhyYxB3sidHlwZSI6ImF1dGhvcml6YXRpb25fY29kZSIsImF1dGhfa2V5IjoicmFuZG9tXzEiLCJ1c2VyX2lkIjoiZm9vIiwiY2xpZW50X2lkIjoiY29kZS1jbGllbnQiLCJzY29wZSI6ImZvbyIsInJlZGlyZWN0X3VyaSI6Imh0dHA6XC9cL2V4YW1wbGUub3JnXC9jb2RlLWNiIiwiY29kZV9jaGFsbGVuZ2UiOiJFOU1lbGhvYTJPd3ZGckVNVEpndUNIYW9lSzF0OFVSV2J1R0pTc3R3LWNNIiwiZXhwaXJlc19hdCI6IjIwMTYtMDEtMDEgMDA6MDU6MDAifQ%3D%3D&state=12345',
            $server->postAuthorize(
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
            )
        );
    }

    public function testAuthorizeTokenPostRedirectUriWithQuery()
    {
        $server = new OAuthServer($this->getClientInfo, $this->keyPair, $this->storage, $this->random, $this->dateTime);
        $this->assertSame(
            'http://example.org/code-cb?keep=this&code=PxOQ%2FysqZ65ozJ8aEsMaQfBuK0jJqyr2UPqvWCiUxUWKPz5C009%2Bv3ShcgGwa93VNogtY1%2FSENKlKmCzHgdMBHsidHlwZSI6ImF1dGhvcml6YXRpb25fY29kZSIsImF1dGhfa2V5IjoicmFuZG9tXzEiLCJ1c2VyX2lkIjoiZm9vIiwiY2xpZW50X2lkIjoiY29kZS1jbGllbnQtcXVlcnktcmVkaXJlY3QiLCJzY29wZSI6ImNvbmZpZyIsInJlZGlyZWN0X3VyaSI6Imh0dHA6XC9cL2V4YW1wbGUub3JnXC9jb2RlLWNiP2tlZXA9dGhpcyIsImNvZGVfY2hhbGxlbmdlIjoiRTlNZWxob2EyT3d2RnJFTVRKZ3VDSGFvZUsxdDhVUldidUdKU3N0dy1jTSIsImV4cGlyZXNfYXQiOiIyMDE2LTAxLTAxIDAwOjA1OjAwIn0%3D&state=12345',
            $server->postAuthorize(
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
            )
        );
    }

    public function testPostToken()
    {
        $server = new OAuthServer($this->getClientInfo, $this->keyPair, $this->storage, $this->random, $this->dateTime);
        $tokenResponse = $server->postToken(
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
        $this->assertSame(
            [
                'access_token' => 'znwcwk0WpP1y0qrUSd/J6KToSlXdceGBaliVLhYYjRESQoVZI1aZTX9cRfBfIpOBnMcyTF3Izs9H8918OwiqBHsidHlwZSI6ImFjY2Vzc190b2tlbiIsImF1dGhfa2V5IjoicmFuZG9tXzEiLCJ1c2VyX2lkIjoiZm9vIiwiY2xpZW50X2lkIjoiY29kZS1jbGllbnQiLCJzY29wZSI6ImNvbmZpZyIsImV4cGlyZXNfYXQiOiIyMDE2LTAxLTAxIDAxOjAwOjAwIn0=',
                'refresh_token' => 'wi5vLrEtTVmTFfI+lLCfVVg3b6punZLQs6+N/8Q67ybHLEqdDzxXYjD3FePW3KmMW0NhVqMOFge52h8U30lQC3sidHlwZSI6InJlZnJlc2hfdG9rZW4iLCJhdXRoX2tleSI6InJhbmRvbV8xIiwidXNlcl9pZCI6ImZvbyIsImNsaWVudF9pZCI6ImNvZGUtY2xpZW50Iiwic2NvcGUiOiJjb25maWcifQ==',
                'token_type' => 'bearer',
                'expires_in' => 3600,
            ],
            $tokenResponse
        );
    }

    public function testPostTokenSecret()
    {
        $server = new OAuthServer($this->getClientInfo, $this->keyPair, $this->storage, $this->random, $this->dateTime);
        $tokenResponse = $server->postToken(
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
            $tokenResponse
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
        $server = new OAuthServer($this->getClientInfo, $this->keyPair, $this->storage, $this->random, $this->dateTime);
        $server->postToken(
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
        $server = new OAuthServer($this->getClientInfo, $this->keyPair, $this->storage, $this->random, $this->dateTime);
        $server->postToken(
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
        $server = new OAuthServer($this->getClientInfo, $this->keyPair, $this->storage, $this->random, $this->dateTime);
        // add random_1 to storage
        $this->storage->storeAuthorization('foo', 'code-client', 'config', 'random_1');
        $server->postToken(
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
        $server = new OAuthServer($this->getClientInfo, $this->keyPair, $this->storage, $this->random, new DateTime('2017-01-01'));
        $server->postToken(
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

        $server = new OAuthServer($this->getClientInfo, $this->keyPair, $this->storage, $this->random, $this->dateTime);
        $tokenResponse = $server->postToken(
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
            $tokenResponse
        );
    }
}
