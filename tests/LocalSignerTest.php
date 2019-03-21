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

use fkooman\OAuth\Server\LocalSigner;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\TestCase;

class LocalSignerTest extends TestCase
{
    /**
     * @return void
     */
    public function testSign()
    {
        $localSigner = new LocalSigner(Base64UrlSafe::decode('pCPTNvjDByHTwqjTlcWOX9xEG0cWJsHf4B1Vc6GJ_3g'));
        $this->assertSame('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.p0tzemsBv_XCxD8laFsr1iXdq0U-mGnYPmto_ogVXj8', $localSigner->sign(['foo' => 'bar']));
    }

    /**
     * @return void
     */
    public function testVerify()
    {
        $localSigner = new LocalSigner(Base64UrlSafe::decode('pCPTNvjDByHTwqjTlcWOX9xEG0cWJsHf4B1Vc6GJ_3g'));
        $this->assertSame(
            [
                'foo' => 'bar',
            ],
            $localSigner->verify('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.p0tzemsBv_XCxD8laFsr1iXdq0U-mGnYPmto_ogVXj8')
        );
    }

    /**
     * @return void
     */
    public function testNoDot()
    {
        $localSigner = new LocalSigner(Base64UrlSafe::decode('pCPTNvjDByHTwqjTlcWOX9xEG0cWJsHf4B1Vc6GJ_3g'));
        $this->assertFalse($localSigner->verify('NO_DOT'));
    }

    /**
     * @return void
     */
    public function testVerifyWrongKey()
    {
        $localSigner = new LocalSigner(Base64UrlSafe::decode('5Zo4eJa3Nni5RPn1bz0uAZao41RqAnWJqD9dYrjVqiU'));
        $this->assertFalse($localSigner->verify('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.p0tzemsBv_XCxD8laFsr1iXdq0U-mGnYPmto_ogVXj8'));
    }
}
