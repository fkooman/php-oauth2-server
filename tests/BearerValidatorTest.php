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
use fkooman\OAuth\Server\BearerValidator;
use fkooman\OAuth\Server\ClientInfo;
use fkooman\OAuth\Server\Exception\InsufficientScopeException;
use fkooman\OAuth\Server\Exception\InvalidTokenException;
use fkooman\OAuth\Server\Storage;
use fkooman\OAuth\Server\TokenInfo;
use PDO;
use PHPUnit\Framework\TestCase;

class BearerValidatorTest extends TestCase
{
    /** @var array */
    private $oauthClients;

    /** @var \fkooman\OAuth\Server\BearerValidator */
    private $validator;

    /** @var \fkooman\OAuth\Server\Storage */
    private $storage;

    public function setUp()
    {
        $this->oauthClients = [
            'code-client' => [
                'redirect_uri_list' => ['http://example.org/code-cb'],
                'display_name' => 'Code Client',
            ],
        ];

        $getClientInfo = function ($clientId) {
            if (!array_key_exists($clientId, $this->oauthClients)) {
                return false;
            }

            return new ClientInfo($this->oauthClients[$clientId]);
        };

        $this->storage = new Storage(new PDO('sqlite::memory:'));
        $this->storage->init();
        $this->validator = new BearerValidator(
            $this->storage,
            $getClientInfo,
            new TestTokenSigner(new DateTime('2016-01-01'))
        );
        $this->validator->setDateTime(new DateTime('2016-01-01'));
    }

    public function testValidToken()
    {
        $this->storage->storeAuthorization('foo', 'code-client', 'config', 'random_1');
        $tokenInfo = $this->validator->validate('Bearer eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiYXV0aF9rZXkiOiJyYW5kb21fMSIsInVzZXJfaWQiOiJmb28iLCJjbGllbnRfaWQiOiJjb2RlLWNsaWVudCIsInNjb3BlIjoiY29uZmlnIiwiZXhwaXJlc19hdCI6IjIwMTYtMDEtMDEgMDE6MDA6MDAifQ');
        $this->assertSame('random_1', $tokenInfo->getAuthKey());
        $this->assertSame('foo', $tokenInfo->getUserId());
        $this->assertSame('config', $tokenInfo->getScope());
//        $this->assertSame(3600, $tokenInfo->getExpiresIn(new DateTime('2016-01-01')));
        $this->assertNull($tokenInfo->getIssuer());
    }

    public function testDeletedClient()
    {
        try {
            $this->oauthClients = [];
            $this->validator->validate('Bearer eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiYXV0aF9rZXkiOiJyYW5kb21fMSIsInVzZXJfaWQiOiJmb28iLCJjbGllbnRfaWQiOiJjb2RlLWNsaWVudCIsInNjb3BlIjoiY29uZmlnIiwiZXhwaXJlc19hdCI6IjIwMTYtMDEtMDEgMDE6MDA6MDAifQ');
            $this->fail();
        } catch (InvalidTokenException $e) {
            $this->assertSame('client no longer registered', $e->getDescription());
        }
    }

    public function testInvalidSyntax()
    {
        try {
            $this->validator->validate('Bearer %%%%');
            $this->fail();
        } catch (InvalidTokenException $e) {
            $this->assertSame('bearer credential syntax error', $e->getDescription());
        }
    }

    public function testExpiredToken()
    {
        try {
            $this->validator->validate('Bearer eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiYXV0aF9rZXkiOiJyYW5kb21fMSIsInVzZXJfaWQiOiJmb28iLCJjbGllbnRfaWQiOiJjb2RlLWNsaWVudCIsInNjb3BlIjoiY29uZmlnIiwiZXhwaXJlc19hdCI6IjIwMTUtMDEtMDEgMDE6MDA6MDAifQo');
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
            $this->assertSame('bearer credential syntax error', $e->getDescription());
        }
    }

    public function testAnyScope()
    {
        try {
            $tokenInfo = new TokenInfo(
                'auth_key',
                'user_id',
                'client_id',
                'foo bar'
            );
            BearerValidator::requireAnyScope($tokenInfo, ['baz', 'bar', 'foo']);
            $this->assertTrue(true);
        } catch (InsufficientScopeException $e) {
            $this->fail();
        }
    }

    public function testAllScope()
    {
        try {
            $tokenInfo = new TokenInfo(
                'auth_key',
                'user_id',
                'client_id',
                'foo bar baz'
            );
            BearerValidator::requireAllScope($tokenInfo, ['baz', 'bar', 'foo']);
            $this->assertTrue(true);
        } catch (InsufficientScopeException $e) {
            $this->fail();
        }
    }

    public function testAnyScopeMissingAll()
    {
        try {
            $tokenInfo = new TokenInfo(
                'auth_key',
                'user_id',
                'client_id',
                'foo bar'
            );
            BearerValidator::requireAnyScope($tokenInfo, ['baz', 'def']);
            $this->fail();
        } catch (InsufficientScopeException $e) {
            $this->assertSame('not any of scopes "baz def" granted', $e->getDescription());
        }
    }

    public function testAllScopeMissingOne()
    {
        try {
            $tokenInfo = new TokenInfo(
                'auth_key',
                'user_id',
                'client_id',
                'foo bar'
            );
            BearerValidator::requireAllScope($tokenInfo, ['baz', 'bar', 'foo']);
            $this->fail();
        } catch (InsufficientScopeException $e) {
            $this->assertSame('scope "baz" not granted', $e->getDescription());
        }
    }

    public function testCodeAsAccessToken()
    {
        try {
            $this->validator->validate('Bearer eyJ0eXBlIjoiYXV0aG9yaXphdGlvbl9jb2RlIiwiYXV0aF9rZXkiOiJyYW5kb21fMSIsInVzZXJfaWQiOiJmb28iLCJjbGllbnRfaWQiOiJjb2RlLWNsaWVudCIsInNjb3BlIjoiY29uZmlnIiwicmVkaXJlY3RfdXJpIjoiaHR0cDpcL1wvZXhhbXBsZS5vcmdcL2NvZGUtY2IiLCJjb2RlX2NoYWxsZW5nZSI6IkU5TWVsaG9hMk93dkZyRU1USmd1Q0hhb2VLMXQ4VVJXYnVHSlNzdHctY00iLCJleHBpcmVzX2F0IjoiMjAxNi0wMS0wMSAwMDowNTowMCJ9');
            $this->fail();
        } catch (InvalidTokenException $e) {
            $this->assertSame('expected "access_token", got "authorization_code"', $e->getDescription());
        }
    }
}
