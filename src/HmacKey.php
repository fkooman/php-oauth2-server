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

namespace fkooman\OAuth\Server;

use LengthException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use TypeError;

class HmacKey
{
    // strlen(hash('sha256', '', true))
    const KEY_LENGTH_BYTES = 32;

    /** @var string */
    private $secretKey;

    /**
     * @param string $secretKey
     */
    public function __construct($secretKey)
    {
        if (self::KEY_LENGTH_BYTES !== Binary::safeStrlen($secretKey)) {
            throw new LengthException('invalid key length');
        }
        $this->secretKey = $secretKey;
    }

    /**
     * @return self
     */
    public static function generate()
    {
        return new self(\random_bytes(self::KEY_LENGTH_BYTES));
    }

    /**
     * @return string
     */
    public function encode()
    {
        return Base64UrlSafe::encodeUnpadded($this->secretKey);
    }

    /**
     * @param string $encodedKey
     *
     * @return self
     */
    public static function fromEncodedString($encodedKey)
    {
        if (!\is_string($encodedKey)) {
            throw new TypeError('argument 1 must be string');
        }

        return new self(Base64UrlSafe::decode($encodedKey));
    }

    /**
     * @return string
     */
    public function raw()
    {
        return $this->secretKey;
    }
}
