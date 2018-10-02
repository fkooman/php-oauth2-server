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

use fkooman\OAuth\Server\SodiumSigner;
use PHPUnit\Framework\TestCase;

class SodiumSignerTest extends TestCase
{
    public function testSign()
    {
        $sodiumSigner = new SodiumSigner(\file_get_contents(\sprintf('%s/data/server.key', __DIR__)));
        $this->assertSame(
            's2J7rZp6UK9xiXSa9fZ6CjDbotGnx7YrAtD84w5WyMU_-RnkVlw6FxCsPSrgP7njSXgL-Wsa6O8HvEW3aSYaAXsiZm9vIjoiYmFyIn0',
            $sodiumSigner->sign(['foo' => 'bar'])
        );
    }

    public function testVerify()
    {
        $sodiumSigner = new SodiumSigner(\file_get_contents(\sprintf('%s/data/server.key', __DIR__)));
        $this->assertSame(
            [
                'foo' => 'bar',
            ],
            $sodiumSigner->verify(
                's2J7rZp6UK9xiXSa9fZ6CjDbotGnx7YrAtD84w5WyMU_-RnkVlw6FxCsPSrgP7njSXgL-Wsa6O8HvEW3aSYaAXsiZm9vIjoiYmFyIn0'
            )
        );
    }

    public function testSignVerifyWrongKey()
    {
        $sodiumSigner = new SodiumSigner(\file_get_contents(\sprintf('%s/data/server_2.key', __DIR__)));
        $this->assertFalse(
            $sodiumSigner->verify(
                's2J7rZp6UK9xiXSa9fZ6CjDbotGnx7YrAtD84w5WyMU_-RnkVlw6FxCsPSrgP7njSXgL-Wsa6O8HvEW3aSYaAXsiZm9vIjoiYmFyIn0'
            )
        );
    }
}
