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
use fkooman\OAuth\Server\Storage;
use PDO;
use PHPUnit\Framework\TestCase;

class BearerValidatorTest extends TestCase
{
    /** @var \fkooman\OAuth\Server\BearerValidator */
    private $validator;

    /** @var \fkooman\OAuth\Server\Storage */
    private $storage;

    public function setUp()
    {
        $clientDb = new ArrayClientDb(
            [
                'code-client' => [
                    'redirect_uri_list' => ['http://example.org/code-cb'],
                    'display_name' => 'Code Client',
                ],
            ]
        );
        $this->storage = new Storage(new PDO('sqlite::memory:'));
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
        $tokenInfo = $this->validator->validate('Bearer eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiYXV0aF9rZXkiOiJyYW5kb21fMSIsInVzZXJfaWQiOiJmb28iLCJjbGllbnRfaWQiOiJjb2RlLWNsaWVudCIsInNjb3BlIjoiY29uZmlnIiwiZXhwaXJlc19hdCI6IjIwMTYtMDEtMDEgMDE6MDA6MDAifQ');
        $this->assertSame('random_1', $tokenInfo->getAuthKey());
        $this->assertSame('foo', $tokenInfo->getUserId());
        $this->assertSame('config', $tokenInfo->getScope());
    }

    public function testInvalidSignature()
    {
        try {
            $this->storage->storeAuthorization('foo', 'code-client', 'config', 'random_1');
            $this->validator->validate('Bearer eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiYXV0aF9rZXkiOiJpbnZhbGlkX3NpZyIsInVzZXJfaWQiOiJmb28iLCJjbGllbnRfaWQiOiJjb2RlLWNsaWVudCIsInNjb3BlIjoiY29uZmlnIiwiZXhwaXJlc19hdCI6IjIwMTYtMDEtMDEgMDE6MDA6MDAifQ');
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
            $this->validator->validate('Bearer eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiYXV0aF9rZXkiOiJyYW5kb21fMSIsInVzZXJfaWQiOiJmb28iLCJjbGllbnRfaWQiOiJjb2RlLWNsaWVudCIsInNjb3BlIjoiY29uZmlnIiwiZXhwaXJlc19hdCI6IjIwMTYtMDEtMDEgMDE6MDA6MDAifQ');
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
            $this->assertSame('invalid Bearer token', $e->getDescription());
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
