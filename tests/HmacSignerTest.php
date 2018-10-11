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

use fkooman\OAuth\Server\HmacSigner;
use fkooman\OAuth\Server\SecretKey;
use PHPUnit\Framework\TestCase;

class HmacSignerTest extends TestCase
{
    public function testSign()
    {
        $hmacSigner = new HmacSigner(SecretKey::fromEncodedString('pCPTNvjDByHTwqjTlcWOX9xEG0cWJsHf4B1Vc6GJ_3g'));
        $this->assertSame('eyJmb28iOiJiYXIifQ.h65W_W0vrXZOe_jcPjrJH11qevaGE69aAmGPbUn2iUA', $hmacSigner->sign(['foo' => 'bar']));
    }

    public function testVerify()
    {
        $hmacSigner = new HmacSigner(SecretKey::fromEncodedString('pCPTNvjDByHTwqjTlcWOX9xEG0cWJsHf4B1Vc6GJ_3g'));
        $this->assertSame(
            ['foo' => 'bar'],
            $hmacSigner->verify('eyJmb28iOiJiYXIifQ.h65W_W0vrXZOe_jcPjrJH11qevaGE69aAmGPbUn2iUA')
        );
    }

    public function testNoDot()
    {
        $hmacSigner = new HmacSigner(SecretKey::fromEncodedString('pCPTNvjDByHTwqjTlcWOX9xEG0cWJsHf4B1Vc6GJ_3g'));
        $this->assertFalse($hmacSigner->verify('NO_DOT'));
    }

    public function testVerifyWrongKey()
    {
        $hmacSigner = new HmacSigner(SecretKey::fromEncodedString('5Zo4eJa3Nni5RPn1bz0uAZao41RqAnWJqD9dYrjVqiU'));
        $this->assertFalse($hmacSigner->verify('eyJmb28iOiJiYXIifQ.h65W_W0vrXZOe_jcPjrJH11qevaGE69aAmGPbUn2iUA'));
    }
}
