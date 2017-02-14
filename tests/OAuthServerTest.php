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
            'code-client-query-redirect' => [
                'redirect_uri' => 'http://example.org/code-cb?keep=this',
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

        $storage = new Storage(new PDO('sqlite::memory:'));
        $storage->init();

        $this->server = new OAuthServer(
            $getClientInfo,
            base64_decode('2y5vJlGqpjTzwr3Ym3UqNwJuI1BKeLs53fc6Zf84kbYcP2/6Ar7zgiPS6BL4bvCaWN4uatYfuP7Dj/QvdctqJRw/b/oCvvOCI9LoEvhu8JpY3i5q1h+4/sOP9C91y2ol'),
            $storage,
            $random,
            new DateTime('2016-01-01')
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
                ]
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
                ]
            )
        );
    }

    public function testAuthorizeTokenPost()
    {
        $this->assertSame(
            'http://example.org/token-cb#access_token=H00ay1mgpwxdwx74s%2B8tEsSwo583YTHr7IeEfkuIuSHXLjeAmaHwqXwE8JKNV7En7O6FPsRkpM7zvH0DTgfnDnsidHlwZSI6ImFjY2Vzc190b2tlbiIsImtleSI6InJhbmRvbV8xIiwidXNlcl9pZCI6ImZvbyIsImNsaWVudF9pZCI6InRva2VuLWNsaWVudCIsInNjb3BlIjoiY29uZmlnIiwiZXhwaXJlc19hdCI6IjIwMTYtMDEtMDEgMDE6MDA6MDAifQ%3D%3D&state=12345&expires_in=3600',
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

    public function testAuthorizeTokenPostNotApproved()
    {
        $this->assertSame(
            'http://example.org/token-cb#error=access_denied&error_description=user+refused+authorization&state=12345',
            $this->server->postAuthorize(
                [
                    'client_id' => 'token-client',
                    'redirect_uri' => 'http://example.org/token-cb',
                    'response_type' => 'token',
                    'scope' => 'config',
                    'state' => '12345',
                ],
                [
                    'approve' => 'no',
                ],
                'foo'
            )
        );
    }

    public function testAuthorizeCodePost()
    {
        $this->assertSame(
            'http://example.org/code-cb?code=shS5ssHi2XceqPNKg8Kgl5C99O%2FBe7AE80NIajiieyu6VO6dGCZpqwwd91vErN1xnPTGcgxGmPCPctcIeqTjAHsidHlwZSI6ImF1dGhvcml6YXRpb25fY29kZSIsImtleSI6InJhbmRvbV8xIiwidXNlcl9pZCI6ImZvbyIsImNsaWVudF9pZCI6ImNvZGUtY2xpZW50Iiwic2NvcGUiOiJjb25maWciLCJyZWRpcmVjdF91cmkiOiJodHRwOlwvXC9leGFtcGxlLm9yZ1wvY29kZS1jYiIsImNvZGVfY2hhbGxlbmdlIjoiRTlNZWxob2EyT3d2RnJFTVRKZ3VDSGFvZUsxdDhVUldidUdKU3N0dy1jTSIsImV4cGlyZXNfYXQiOiIyMDE2LTAxLTAxIDAwOjA1OjAwIn0%3D&state=12345',
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

    public function testAuthorizeTokenPostRedirectUriWithQuery()
    {
        $this->assertSame(
            'http://example.org/code-cb?keep=this&code=ZX0m9VnrflEC0ObIZ%2Bk3XZVa6Dr%2FaqmGg29dIDYvZmMEmWjIPP6z11A4stwLHkzLOXDOSaDnO6l23%2FME3gpbCHsidHlwZSI6ImF1dGhvcml6YXRpb25fY29kZSIsImtleSI6InJhbmRvbV8xIiwidXNlcl9pZCI6ImZvbyIsImNsaWVudF9pZCI6ImNvZGUtY2xpZW50LXF1ZXJ5LXJlZGlyZWN0Iiwic2NvcGUiOiJjb25maWciLCJyZWRpcmVjdF91cmkiOiJodHRwOlwvXC9leGFtcGxlLm9yZ1wvY29kZS1jYj9rZWVwPXRoaXMiLCJjb2RlX2NoYWxsZW5nZSI6IkU5TWVsaG9hMk93dkZyRU1USmd1Q0hhb2VLMXQ4VVJXYnVHSlNzdHctY00iLCJleHBpcmVzX2F0IjoiMjAxNi0wMS0wMSAwMDowNTowMCJ9&state=12345',
            $this->server->postAuthorize(
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
        $tokenResponse = $this->server->postToken(
            [
                'grant_type' => 'authorization_code',
                'code' => 'shS5ssHi2XceqPNKg8Kgl5C99O/Be7AE80NIajiieyu6VO6dGCZpqwwd91vErN1xnPTGcgxGmPCPctcIeqTjAHsidHlwZSI6ImF1dGhvcml6YXRpb25fY29kZSIsImtleSI6InJhbmRvbV8xIiwidXNlcl9pZCI6ImZvbyIsImNsaWVudF9pZCI6ImNvZGUtY2xpZW50Iiwic2NvcGUiOiJjb25maWciLCJyZWRpcmVjdF91cmkiOiJodHRwOlwvXC9leGFtcGxlLm9yZ1wvY29kZS1jYiIsImNvZGVfY2hhbGxlbmdlIjoiRTlNZWxob2EyT3d2RnJFTVRKZ3VDSGFvZUsxdDhVUldidUdKU3N0dy1jTSIsImV4cGlyZXNfYXQiOiIyMDE2LTAxLTAxIDAwOjA1OjAwIn0=',
                'redirect_uri' => 'http://example.org/code-cb',
                'client_id' => 'code-client',
                'code_verifier' => 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
            ],
            null,
            null
        );
        $this->assertSame(
            [
                'access_token' => 'pr/mlAkRzsPXb5X1h3UEeNpLfqFyD550vGrwYc7kuGD01sWJ84DDy4JdlWlFHR4a7dBXPAkS/BPi8Yuc26PqCXsidHlwZSI6ImFjY2Vzc190b2tlbiIsImtleSI6InJhbmRvbV8xIiwidXNlcl9pZCI6ImZvbyIsImNsaWVudF9pZCI6ImNvZGUtY2xpZW50Iiwic2NvcGUiOiJjb25maWciLCJleHBpcmVzX2F0IjoiMjAxNi0wMS0wMSAwMTowMDowMCJ9',
                'token_type' => 'bearer',
                'expires_in' => 3600,
            ],
            $tokenResponse
        );
    }

    public function testPostTokenSecret()
    {
        $tokenResponse = $this->server->postToken(
            [
                'grant_type' => 'authorization_code',
                'code' => 'CQZcqFMFWBOgUmi2ugLwLAkIfyPb1sOhYJdZOefIKDUa5qarG+b0b8PdmJtu1vMnyZtjYY9jclvV6BYpkN4ZCHsidHlwZSI6ImF1dGhvcml6YXRpb25fY29kZSIsImtleSI6InJhbmRvbV8xIiwidXNlcl9pZCI6ImZvbyIsImNsaWVudF9pZCI6ImNvZGUtY2xpZW50LXNlY3JldCIsInNjb3BlIjoiY29uZmlnIiwicmVkaXJlY3RfdXJpIjoiaHR0cDpcL1wvZXhhbXBsZS5vcmdcL2NvZGUtY2IiLCJjb2RlX2NoYWxsZW5nZSI6IkU5TWVsaG9hMk93dkZyRU1USmd1Q0hhb2VLMXQ4VVJXYnVHSlNzdHctY00iLCJleHBpcmVzX2F0IjoiMjAxNi0wMS0wMSAwMDowNTowMCJ9',
                'redirect_uri' => 'http://example.org/code-cb',
                'client_id' => 'code-client-secret',
            ],
            'code-client-secret',
            '123456'
        );
        $this->assertSame(
            [
                'access_token' => 'MkDDFOJfV+WyuRBnRQpKmCKS1el6iNFxjcTSIVU2tyyqyRzfaxo8jIP1DFI51wIvvbis3BV70FAY0Eb3hLiJAHsidHlwZSI6ImFjY2Vzc190b2tlbiIsImtleSI6InJhbmRvbV8xIiwidXNlcl9pZCI6ImZvbyIsImNsaWVudF9pZCI6ImNvZGUtY2xpZW50LXNlY3JldCIsInNjb3BlIjoiY29uZmlnIiwiZXhwaXJlc19hdCI6IjIwMTYtMDEtMDEgMDE6MDA6MDAifQ==',
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

    public function testSignedAccessToken()
    {
        $this->assertSame(
            'http://example.org/token-cb#access_token=H00ay1mgpwxdwx74s%2B8tEsSwo583YTHr7IeEfkuIuSHXLjeAmaHwqXwE8JKNV7En7O6FPsRkpM7zvH0DTgfnDnsidHlwZSI6ImFjY2Vzc190b2tlbiIsImtleSI6InJhbmRvbV8xIiwidXNlcl9pZCI6ImZvbyIsImNsaWVudF9pZCI6InRva2VuLWNsaWVudCIsInNjb3BlIjoiY29uZmlnIiwiZXhwaXJlc19hdCI6IjIwMTYtMDEtMDEgMDE6MDA6MDAifQ%3D%3D&state=12345&expires_in=3600',
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
