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
            'token-client' => [
                'redirect_uri_list' => ['http://example.org/token-cb'],
                'display_name' => 'Token Client',
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
            '2y5vJlGqpjTzwr3Ym3UqNwJuI1BKeLs53fc6Zf84kbYcP2/6Ar7zgiPS6BL4bvCaWN4uatYfuP7Dj/QvdctqJRw/b/oCvvOCI9LoEvhu8JpY3i5q1h+4/sOP9C91y2ol'
        );
        $this->validator->setDateTime(new DateTime('2016-01-01'));
    }

    public function testValidToken()
    {
        $this->storage->storeAuthorization('foo', 'code-client', 'config', 'random_1');
        $tokenInfo = $this->validator->validate('Bearer znwcwk0WpP1y0qrUSd/J6KToSlXdceGBaliVLhYYjRESQoVZI1aZTX9cRfBfIpOBnMcyTF3Izs9H8918OwiqBHsidHlwZSI6ImFjY2Vzc190b2tlbiIsImF1dGhfa2V5IjoicmFuZG9tXzEiLCJ1c2VyX2lkIjoiZm9vIiwiY2xpZW50X2lkIjoiY29kZS1jbGllbnQiLCJzY29wZSI6ImNvbmZpZyIsImV4cGlyZXNfYXQiOiIyMDE2LTAxLTAxIDAxOjAwOjAwIn0=');
        $this->assertSame('random_1', $tokenInfo->getAuthKey());
        $this->assertSame('foo', $tokenInfo->getUserId());
        $this->assertSame('config', $tokenInfo->getScope());
        $this->assertSame(3600, $tokenInfo->getExpiresIn(new DateTime('2016-01-01')));
        $this->assertNull($tokenInfo->getIssuer());
    }

    public function testValidBase64UrlSafeToken()
    {
        $this->storage->storeAuthorization('foo', 'code-client', 'config', 'random_1');
        $tokenInfo = $this->validator->validate('Bearer znwcwk0WpP1y0qrUSd_J6KToSlXdceGBaliVLhYYjRESQoVZI1aZTX9cRfBfIpOBnMcyTF3Izs9H8918OwiqBHsidHlwZSI6ImFjY2Vzc190b2tlbiIsImF1dGhfa2V5IjoicmFuZG9tXzEiLCJ1c2VyX2lkIjoiZm9vIiwiY2xpZW50X2lkIjoiY29kZS1jbGllbnQiLCJzY29wZSI6ImNvbmZpZyIsImV4cGlyZXNfYXQiOiIyMDE2LTAxLTAxIDAxOjAwOjAwIn0');
        $this->assertSame('random_1', $tokenInfo->getAuthKey());
        $this->assertSame('foo', $tokenInfo->getUserId());
        $this->assertSame('config', $tokenInfo->getScope());
        $this->assertSame(3600, $tokenInfo->getExpiresIn(new DateTime('2016-01-01')));
        $this->assertNull($tokenInfo->getIssuer());
    }

    public function testDeletedClient()
    {
        try {
            $this->oauthClients = [];
            $this->validator->validate('Bearer znwcwk0WpP1y0qrUSd/J6KToSlXdceGBaliVLhYYjRESQoVZI1aZTX9cRfBfIpOBnMcyTF3Izs9H8918OwiqBHsidHlwZSI6ImFjY2Vzc190b2tlbiIsImF1dGhfa2V5IjoicmFuZG9tXzEiLCJ1c2VyX2lkIjoiZm9vIiwiY2xpZW50X2lkIjoiY29kZS1jbGllbnQiLCJzY29wZSI6ImNvbmZpZyIsImV4cGlyZXNfYXQiOiIyMDE2LTAxLTAxIDAxOjAwOjAwIn0=');
            $this->fail();
        } catch (InvalidTokenException $e) {
            $this->assertSame('client no longer registered', $e->getDescription());
        }
    }

    public function testValidPublicKeyToken()
    {
        $this->validator->setForeignKeys(
            [
                'issuer.example.org' => 'Jb+A8dkDCXwH2LWyKX6H6BmJearfrH/SGVXSqjL2QNs=',
            ]
        );
        $tokenInfo = $this->validator->validate('Bearer BMrr3RdJgGSRxzDyC/89mfcrpH7eva9czHp4s4FH8YjsNp9p8w2K32+sI6e1FKIGrTuu/R0H6B6oQzrIyJ7FAHsidHlwZSI6ImFjY2Vzc190b2tlbiIsImF1dGhfa2V5IjoicmFuZG9tXzEiLCJ1c2VyX2lkIjoiZm9vIiwiY2xpZW50X2lkIjoidG9rZW4tY2xpZW50Iiwic2NvcGUiOiJjb25maWciLCJleHBpcmVzX2F0IjoiMjAxNi0wMS0wMSAwMTowMDowMCJ9');
        $this->assertSame('random_1', $tokenInfo->getAuthKey());
        $this->assertSame('foo', $tokenInfo->getUserId());
        $this->assertSame('config', $tokenInfo->getScope());
        $this->assertSame(3600, $tokenInfo->getExpiresIn(new DateTime('2016-01-01')));
        $this->assertSame('issuer.example.org', $tokenInfo->getIssuer());
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
            $this->validator->setDateTime(new DateTime('2017-01-01'));
            $this->validator->validate('Bearer znwcwk0WpP1y0qrUSd/J6KToSlXdceGBaliVLhYYjRESQoVZI1aZTX9cRfBfIpOBnMcyTF3Izs9H8918OwiqBHsidHlwZSI6ImFjY2Vzc190b2tlbiIsImF1dGhfa2V5IjoicmFuZG9tXzEiLCJ1c2VyX2lkIjoiZm9vIiwiY2xpZW50X2lkIjoiY29kZS1jbGllbnQiLCJzY29wZSI6ImNvbmZpZyIsImV4cGlyZXNfYXQiOiIyMDE2LTAxLTAxIDAxOjAwOjAwIn0=');
            $this->fail();
        } catch (InvalidTokenException $e) {
            $this->assertSame('token expired', $e->getDescription());
        }
    }

    public function testInvalidSignatureWrongKey()
    {
        $this->storage->storeAuthorization('foo', 'token-client', 'config', 'random_1');
        try {
            $this->validator->validate('Bearer rFiR9xhpCfo0fUI6hs9kYIAeAzISfBW5xlY5xUJQPibvQVmt+Xa/GsGDtdZukmL8V8Z6i6AXjqfKQLUcSEVKAnsidHlwZSI6ImFjY2Vzc190b2tlbiIsImF1dGhfa2V5IjoiZjNiMTVkODhjZDI4MGQ2NWM5NDlhZjA2NWJiNTg5NWYiLCJ1c2VyX2lkIjoiZm9vIiwiY2xpZW50X2lkIjoiZGVtb19jbGllbnQiLCJzY29wZSI6ImZvbyBiYXIiLCJleHBpcmVzX2F0IjoiMjAxNy0xMS0xNCAxNjo0NDoyNyJ9');
            $this->fail();
        } catch (InvalidTokenException $e) {
            $this->assertSame('invalid signature', $e->getDescription());
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
                'foo bar',
                new DateTime('2016-01-01')
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
                'foo bar baz',
                new DateTime('2016-01-01')
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
                'foo bar',
                new DateTime('2016-01-01')
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
                'foo bar',
                new DateTime('2016-01-01')
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
            $this->validator->validate('Bearer nmVljssjTwA29QjWrzieuAQjwR0yJo6DodWaTAa72t03WWyGDA8ajTdUy0Dzklrzx4kUjkL7MX/BaE2PUuykBHsidHlwZSI6ImF1dGhvcml6YXRpb25fY29kZSIsImF1dGhfa2V5IjoicmFuZG9tXzEiLCJ1c2VyX2lkIjoiZm9vIiwiY2xpZW50X2lkIjoiY29kZS1jbGllbnQiLCJzY29wZSI6ImNvbmZpZyIsInJlZGlyZWN0X3VyaSI6Imh0dHA6XC9cL2V4YW1wbGUub3JnXC9jb2RlLWNiIiwiY29kZV9jaGFsbGVuZ2UiOiJFOU1lbGhvYTJPd3ZGckVNVEpndUNIYW9lSzF0OFVSV2J1R0pTc3R3LWNNIiwiZXhwaXJlc19hdCI6IjIwMTYtMDEtMDEgMDA6MDU6MDAifQ==');
            $this->fail();
        } catch (InvalidTokenException $e) {
            $this->assertSame('not an access token', $e->getDescription());
        }
    }
}
