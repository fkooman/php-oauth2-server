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

class SodiumSigner implements SignerInterface
{
    /** @var string */
    private $keyPair;

    /**
     * @param string $keyPair
     * @psalm-suppress RedundantConditionGivenDocblockType
     */
    public function __construct($keyPair)
    {
        if (!\is_string($keyPair)) {
            throw new TypeError('argument 1 must be string');
        }
        if (SODIUM_CRYPTO_SIGN_KEYPAIRBYTES !== Binary::safeStrlen($keyPair)) {
            throw new LengthException('invalid keypair length');
        }
        $this->keyPair = $keyPair;
    }

    /**
     * @param array $tokenData
     *
     * @return string
     */
    public function sign(array $tokenData)
    {
        return Base64UrlSafe::encodeUnpadded(
            \sodium_crypto_sign(
                Json::encode($tokenData),
                \sodium_crypto_sign_secretkey($this->keyPair)
            )
        );
    }

    /**
     * @param string $inputStr
     *
     * @return false|array
     * @psalm-suppress RedundantConditionGivenDocblockType
     */
    public function verify($inputStr)
    {
        if (!\is_string($inputStr)) {
            throw new TypeError('argument 1 must be string');
        }
        $decodedStr = Base64UrlSafe::decode(
            // in earlier versions we supported standard Base64 encoding as
            // well, now we only generate Base64UrlSafe strings (without
            // padding), but we still want to accept the old ones as well!
            self::toUnpaddedUrlSafe($inputStr)
        );

        $publicKey = \sodium_crypto_sign_publickey($this->keyPair);
        if (false === $verifiedString = \sodium_crypto_sign_open($decodedStr, $publicKey)) {
            return false;
        }

        return Json::decode($verifiedString);
    }

    /**
     * @param string $inputStr
     *
     * @return string
     */
    private static function toUnpaddedUrlSafe($inputStr)
    {
        return \rtrim(
            \str_replace(
                ['+', '/'],
                ['-', '_'],
                $inputStr
            ),
            '='
        );
    }
}
