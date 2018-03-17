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

use fkooman\OAuth\Server\Exception\InsufficientScopeException;
use fkooman\OAuth\Server\TokenInfo;
use PHPUnit\Framework\TestCase;

class TokenInfoTest extends TestCase
{
    public function testAnyScope()
    {
        try {
            $tokenInfo = new TokenInfo(
                'auth_key',
                'user_id',
                'client_id',
                'foo bar',
                hex2bin('12345abcdefa')
            );
            $tokenInfo->requireAnyScope(['baz', 'bar', 'foo']);
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
                hex2bin('12345abcdefa')
            );
            $tokenInfo->requireAllScope(['baz', 'bar', 'foo']);
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
                hex2bin('12345abcdefa')
            );
            $tokenInfo->requireAnyScope(['baz', 'def']);
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
                hex2bin('12345abcdefa')
            );
            $tokenInfo->requireAllScope(['baz', 'bar', 'foo']);
            $this->fail();
        } catch (InsufficientScopeException $e) {
            $this->assertSame('scope "baz" not granted', $e->getDescription());
        }
    }
}
