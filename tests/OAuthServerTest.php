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
use fkooman\OAuth\Server\ClientInfo;
use fkooman\OAuth\Server\Exception\InvalidClientException;
use fkooman\OAuth\Server\Exception\InvalidGrantException;
use fkooman\OAuth\Server\Exception\InvalidRequestException;
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
                'redirect_uri_list' => ['http://example.org/code-cb'],
                'response_type' => 'code',
                'display_name' => 'Code Client',
                'require_approval' => false,
            ],
            'code-client-query-redirect' => [
                'response_type' => 'code',
                'redirect_uri_list' => ['http://example.org/code-cb?keep=this'],
                'display_name' => 'Code Client',
            ],
            'code-client-secret' => [
                'response_type' => 'code',
                'redirect_uri_list' => ['http://example.org/code-cb'],
                'display_name' => 'Code Client',
                'client_secret' => '123456',
            ],
            'loopback' => [
                'response_type' => 'code',
                'redirect_uri_list' => ['http://127.0.0.1:{PORT}/cb'],
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

        $this->server = new OAuthServer(
            $this->storage,
            $getClientInfo,
            new TestTokenSigner(
                new DateTime('2016-01-01')
            )
        );
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
        $this->assertInstanceOf('\fkooman\OAuth\Server\Http\Response', $authorizeResponse);
        $this->assertSame(
            [
                'Location' => 'http://example.org/code-cb?code=eyJ0eXBlIjoiYXV0aG9yaXphdGlvbl9jb2RlIiwiYXV0aF9rZXkiOiJyYW5kb21fMSIsInVzZXJfaWQiOiJmb28iLCJjbGllbnRfaWQiOiJjb2RlLWNsaWVudCIsInNjb3BlIjoiY29uZmlnIiwicmVkaXJlY3RfdXJpIjoiaHR0cDpcL1wvZXhhbXBsZS5vcmdcL2NvZGUtY2IiLCJjb2RlX2NoYWxsZW5nZSI6IkU5TWVsaG9hMk93dkZyRU1USmd1Q0hhb2VLMXQ4VVJXYnVHSlNzdHctY00iLCJleHBpcmVzX2F0IjoiMjAxNi0wMS0wMSAwMDowNTowMCJ9&state=12345',
            ],
            $authorizeResponse->getHeaders()
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
                'Location' => 'http://example.org/code-cb?code=eyJ0eXBlIjoiYXV0aG9yaXphdGlvbl9jb2RlIiwiYXV0aF9rZXkiOiJyYW5kb21fMSIsInVzZXJfaWQiOiJmb28iLCJjbGllbnRfaWQiOiJjb2RlLWNsaWVudCIsInNjb3BlIjoiZm9vIiwicmVkaXJlY3RfdXJpIjoiaHR0cDpcL1wvZXhhbXBsZS5vcmdcL2NvZGUtY2IiLCJjb2RlX2NoYWxsZW5nZSI6IkU5TWVsaG9hMk93dkZyRU1USmd1Q0hhb2VLMXQ4VVJXYnVHSlNzdHctY00iLCJleHBpcmVzX2F0IjoiMjAxNi0wMS0wMSAwMDowNTowMCJ9&state=12345',
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
                'Location' => 'http://example.org/code-cb?keep=this&code=eyJ0eXBlIjoiYXV0aG9yaXphdGlvbl9jb2RlIiwiYXV0aF9rZXkiOiJyYW5kb21fMSIsInVzZXJfaWQiOiJmb28iLCJjbGllbnRfaWQiOiJjb2RlLWNsaWVudC1xdWVyeS1yZWRpcmVjdCIsInNjb3BlIjoiY29uZmlnIiwicmVkaXJlY3RfdXJpIjoiaHR0cDpcL1wvZXhhbXBsZS5vcmdcL2NvZGUtY2I_a2VlcD10aGlzIiwiY29kZV9jaGFsbGVuZ2UiOiJFOU1lbGhvYTJPd3ZGckVNVEpndUNIYW9lSzF0OFVSV2J1R0pTc3R3LWNNIiwiZXhwaXJlc19hdCI6IjIwMTYtMDEtMDEgMDA6MDU6MDAifQ&state=12345',
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
                'code' => 'eyJ0eXBlIjoiYXV0aG9yaXphdGlvbl9jb2RlIiwiYXV0aF9rZXkiOiJyYW5kb21fMSIsInVzZXJfaWQiOiJmb28iLCJjbGllbnRfaWQiOiJjb2RlLWNsaWVudCIsInNjb3BlIjoiY29uZmlnIiwicmVkaXJlY3RfdXJpIjoiaHR0cDpcL1wvZXhhbXBsZS5vcmdcL2NvZGUtY2IiLCJjb2RlX2NoYWxsZW5nZSI6IkU5TWVsaG9hMk93dkZyRU1USmd1Q0hhb2VLMXQ4VVJXYnVHSlNzdHctY00iLCJleHBpcmVzX2F0IjoiMjAxNi0wMS0wMSAwMDowNTowMCJ9',
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
                'access_token' => 'eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiYXV0aF9rZXkiOiJyYW5kb21fMSIsInVzZXJfaWQiOiJmb28iLCJjbGllbnRfaWQiOiJjb2RlLWNsaWVudCIsInNjb3BlIjoiY29uZmlnIiwiZXhwaXJlc19hdCI6IjIwMTYtMDEtMDEgMDE6MDA6MDAifQ',
                'refresh_token' => 'eyJ0eXBlIjoicmVmcmVzaF90b2tlbiIsImF1dGhfa2V5IjoicmFuZG9tXzEiLCJ1c2VyX2lkIjoiZm9vIiwiY2xpZW50X2lkIjoiY29kZS1jbGllbnQiLCJzY29wZSI6ImNvbmZpZyIsImV4cGlyZXNfYXQiOiIyMDE3LTAxLTAxIDAwOjAwOjAwIn0',
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
                'code' => 'eyJ0eXBlIjoiYXV0aG9yaXphdGlvbl9jb2RlIiwiYXV0aF9rZXkiOiJyYW5kb21fMSIsInVzZXJfaWQiOiJmb28iLCJjbGllbnRfaWQiOiJjb2RlLWNsaWVudC1zZWNyZXQiLCJzY29wZSI6ImNvbmZpZyIsInJlZGlyZWN0X3VyaSI6Imh0dHA6XC9cL2V4YW1wbGUub3JnXC9jb2RlLWNiIiwiY29kZV9jaGFsbGVuZ2UiOiJFOU1lbGhvYTJPd3ZGckVNVEpndUNIYW9lSzF0OFVSV2J1R0pTc3R3LWNNIiwiZXhwaXJlc19hdCI6IjIwMTYtMDEtMDEgMDA6MDU6MDAifQ',
                'redirect_uri' => 'http://example.org/code-cb',
                'client_id' => 'code-client-secret',
            ],
            'code-client-secret',
            '123456'
        );
        $this->assertSame(
            [
                'access_token' => 'eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiYXV0aF9rZXkiOiJyYW5kb21fMSIsInVzZXJfaWQiOiJmb28iLCJjbGllbnRfaWQiOiJjb2RlLWNsaWVudC1zZWNyZXQiLCJzY29wZSI6ImNvbmZpZyIsImV4cGlyZXNfYXQiOiIyMDE2LTAxLTAxIDAxOjAwOjAwIn0',
                'refresh_token' => 'eyJ0eXBlIjoicmVmcmVzaF90b2tlbiIsImF1dGhfa2V5IjoicmFuZG9tXzEiLCJ1c2VyX2lkIjoiZm9vIiwiY2xpZW50X2lkIjoiY29kZS1jbGllbnQtc2VjcmV0Iiwic2NvcGUiOiJjb25maWciLCJleHBpcmVzX2F0IjoiMjAxNy0wMS0wMSAwMDowMDowMCJ9',
                'token_type' => 'bearer',
                'expires_in' => 3600,
            ],
            json_decode($tokenResponse->getBody(), true)
        );
    }

    public function testPostTokenMissingCodeVerifierPublicClient()
    {
        try {
            $this->storage->storeAuthorization('foo', 'code-client', 'config', 'random_1');
            $tokenResponse = $this->server->postToken(
                [
                    'grant_type' => 'authorization_code',
                    'code' => 'eyJ0eXBlIjoiYXV0aG9yaXphdGlvbl9jb2RlIiwiYXV0aF9rZXkiOiJyYW5kb21fMSIsInVzZXJfaWQiOiJmb28iLCJjbGllbnRfaWQiOiJjb2RlLWNsaWVudCIsInNjb3BlIjoiY29uZmlnIiwicmVkaXJlY3RfdXJpIjoiaHR0cDpcL1wvZXhhbXBsZS5vcmdcL2NvZGUtY2IiLCJjb2RlX2NoYWxsZW5nZSI6IkU5TWVsaG9hMk93dkZyRU1USmd1Q0hhb2VLMXQ4VVJXYnVHSlNzdHctY00iLCJleHBpcmVzX2F0IjoiMjAxNi0wMS0wMSAwMDowNTowMCJ9',
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

    public function testPostTokenSecretInvalid()
    {
        try {
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
            $this->fail();
        } catch (InvalidClientException $e) {
            $this->assertSame('invalid credentials (invalid authenticating pass)', $e->getDescription());
        }
    }

    public function testPostReuseCode()
    {
        try {
            $this->storage->storeAuthorization('foo', 'code-client', 'config', 'random_1');
            $this->storage->logAuthKey('random_1');
            $this->server->postToken(
                [
                    'grant_type' => 'authorization_code',
                    'code' => 'eyJ0eXBlIjoiYXV0aG9yaXphdGlvbl9jb2RlIiwiYXV0aF9rZXkiOiJyYW5kb21fMSIsInVzZXJfaWQiOiJmb28iLCJjbGllbnRfaWQiOiJjb2RlLWNsaWVudCIsInNjb3BlIjoiY29uZmlnIiwicmVkaXJlY3RfdXJpIjoiaHR0cDpcL1wvZXhhbXBsZS5vcmdcL2NvZGUtY2IiLCJjb2RlX2NoYWxsZW5nZSI6IkU5TWVsaG9hMk93dkZyRU1USmd1Q0hhb2VLMXQ4VVJXYnVHSlNzdHctY00iLCJleHBpcmVzX2F0IjoiMjAxNi0wMS0wMSAwMDowNTowMCJ9',
                    'redirect_uri' => 'http://example.org/code-cb',
                    'client_id' => 'code-client',
                    'code_verifier' => 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
                ],
                null,
                null
            );
            $this->fail();
        } catch (InvalidGrantException $e) {
            $this->assertSame('"authorization_code" reuse', $e->getDescription());
        }
    }

    public function testExpiredCode()
    {
        try {
            $this->server->postToken(
                [
                    'grant_type' => 'authorization_code',
                    'code' => 'eyJ0eXBlIjoiYXV0aG9yaXphdGlvbl9jb2RlIiwiYXV0aF9rZXkiOiJyYW5kb21fMSIsInVzZXJfaWQiOiJmb28iLCJjbGllbnRfaWQiOiJjb2RlLWNsaWVudCIsInNjb3BlIjoiY29uZmlnIiwicmVkaXJlY3RfdXJpIjoiaHR0cDpcL1wvZXhhbXBsZS5vcmdcL2NvZGUtY2IiLCJjb2RlX2NoYWxsZW5nZSI6IkU5TWVsaG9hMk93dkZyRU1USmd1Q0hhb2VLMXQ4VVJXYnVHSlNzdHctY00iLCJleHBpcmVzX2F0IjoiMjAxNS0wMS0wMSAwMDowMDowMCJ9',
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

    public function testAccessTokenAsCode()
    {
        try {
            $this->storage->storeAuthorization('foo', 'code-client', 'config', 'random_1');
            $this->server->postToken(
                [
                    'grant_type' => 'authorization_code',
                    'code' => 'eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiYXV0aF9rZXkiOiJyYW5kb21fMSIsInVzZXJfaWQiOiJmb28iLCJjbGllbnRfaWQiOiJjb2RlLWNsaWVudCIsInNjb3BlIjoiY29uZmlnIiwiZXhwaXJlc19hdCI6IjIwMTYtMDEtMDEgMDE6MDA6MDAifQ',
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

    public function testRefreshTokenWithoutExpiry()
    {
        // this is an "old" refresh_token that did not yet contain "expires_at"
        //
        // the authorization MUST exist for the refresh token to work
        $this->storage->storeAuthorization('foo', 'code-client', 'config', 'random_1');
        $tokenResponse = $this->server->postToken(
            [
                'grant_type' => 'refresh_token',
                'refresh_token' => 'eyJ0eXBlIjoicmVmcmVzaF90b2tlbiIsImF1dGhfa2V5IjoicmFuZG9tXzEiLCJ1c2VyX2lkIjoiZm9vIiwiY2xpZW50X2lkIjoiY29kZS1jbGllbnQiLCJzY29wZSI6ImNvbmZpZyJ9',
                'scope' => 'config',
            ],
            null,
            null
        );
        $this->assertSame(
            [
                'access_token' => 'eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiYXV0aF9rZXkiOiJyYW5kb21fMSIsInVzZXJfaWQiOiJmb28iLCJjbGllbnRfaWQiOiJjb2RlLWNsaWVudCIsInNjb3BlIjoiY29uZmlnIiwiZXhwaXJlc19hdCI6IjIwMTYtMDEtMDEgMDE6MDA6MDAifQ',
                'token_type' => 'bearer',
                'expires_in' => 3600,
            ],
            json_decode($tokenResponse->getBody(), true)
        );
    }

    public function testNonExpiredRefreshToken()
    {
        $this->storage->storeAuthorization('foo', 'code-client-secret', 'config', 'random_1');
        $tokenResponse = $this->server->postToken(
            [
                'grant_type' => 'refresh_token',
                'refresh_token' => 'eyJ0eXBlIjoicmVmcmVzaF90b2tlbiIsImF1dGhfa2V5IjoicmFuZG9tXzEiLCJ1c2VyX2lkIjoiZm9vIiwiY2xpZW50X2lkIjoiY29kZS1jbGllbnQtc2VjcmV0Iiwic2NvcGUiOiJjb25maWciLCJleHBpcmVzX2F0IjoiMjAxNy0wMS0wMSAwMDowMDowMCJ9',
                'scope' => 'config',
            ],
            'code-client-secret',
            '123456'
        );
        $this->assertSame(
            [
                'access_token' => 'eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiYXV0aF9rZXkiOiJyYW5kb21fMSIsInVzZXJfaWQiOiJmb28iLCJjbGllbnRfaWQiOiJjb2RlLWNsaWVudC1zZWNyZXQiLCJzY29wZSI6ImNvbmZpZyIsImV4cGlyZXNfYXQiOiIyMDE2LTAxLTAxIDAxOjAwOjAwIn0',
                'token_type' => 'bearer',
                'expires_in' => 3600,
            ],
            json_decode($tokenResponse->getBody(), true)
        );
    }

    public function testExpiredRefreshToken()
    {
        try {
            $this->storage->storeAuthorization('foo', 'code-client-secret', 'config', 'random_1');
            $tokenResponse = $this->server->postToken(
                [
                    'grant_type' => 'refresh_token',
                    'refresh_token' => 'eyJ0eXBlIjoicmVmcmVzaF90b2tlbiIsImF1dGhfa2V5IjoicmFuZG9tXzEiLCJ1c2VyX2lkIjoiZm9vIiwiY2xpZW50X2lkIjoiY29kZS1jbGllbnQtc2VjcmV0Iiwic2NvcGUiOiJjb25maWciLCJleHBpcmVzX2F0IjoiMjAxNS0wMS0wMSAwMDowMDowMCJ9Cg',
                    'scope' => 'config',
                ],
                'code-client-secret',
                '123456'
            );
        } catch (InvalidGrantException $e) {
            $this->assertSame('"refresh_token" expired', $e->getDescription());
        }
    }

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
