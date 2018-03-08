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

use fkooman\OAuth\Server\Exception\ServerErrorException;
use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Base64UrlSafe;

class SodiumSigner implements SignerInterface
{
    /** @var string|null */
    private $secretKey;

    /** @var array */
    private $publicKeyList;

    /**
     * @param string|null $secretKey
     * @param array       $publicKeyList
     */
    public function __construct($secretKey = null, array $publicKeyList = [])
    {
        $this->secretKey = $secretKey;
        // XXX extract the public key from secretKey thingy and add it to
        // publicKeyList and append the provided publicKeyList to this list
        $this->publicKeyList = $publicKeyList;
    }

    /**
     * @param array $listOfClaims
     *
     * @return string
     */
    public function sign(array $listOfClaims)
    {
        if (null === $this->secretKey) {
            throw new ServerErrorException('secret key MUST be set');
        }

        $jsonString = json_encode($listOfClaims);
        // XXX json error last
        if (false === $jsonString) {
            throw new ServerErrorException('unable to encode JSON');
        }

        // XXX handle errors better! e.g. with keys
        // Base64UrlSafe without padding
        return rtrim(
            Base64UrlSafe::encode(
                sodium_crypto_sign(
                    $jsonString,
                    sodium_crypto_sign_secretkey($this->secretKey)
                )
            ),
            '='
        );
    }

    /**
     * @param string $receivedCodeToken
     *
     * @return array
     */
    public function verify($receivedCodeToken)
    {
        if (0 === count($this->publicKeyList)) {
            throw new ServerErrorException('at least one public key MUST be set');
        }

        $receivedCodeToken = self::normalize($receivedCodeToken);

        // Base64UrlSafe decode
        try {
            if (false === $decodedReceivedCodeToken = Base64UrlSafe::decode($receivedCodeToken)) {
                // paragonie/constant_time_encoding v1.0.1 sometimes returns
                // false when decoding fails, so handle this here as well
                throw new RangeException('Base64 decode error');
            }
        } catch (RangeException $e) {
            throw new ParseException('Base64 decode error');
        }

        // Verify signature and extract JSON

        $str = sodium_crypto_sign_open($signedStr, sodium_crypto_sign_publickey($this->keyPair));
        if (false === $str) {
            throw new ParseException('invalid signature');
        }
        $codeTokenInfo = json_decode($str, true);
        if (null === $codeTokenInfo && JSON_ERROR_NONE !== json_last_error()) {
            throw new ParseException('unable to decode JSON');
        }

        return $codeTokenInfo;
    }

    /**
     * @param string $receivedCodeToken
     *
     * @return string
     */
    private static function normalize($receivedCodeToken)
    {
        // in earlier versions we supported standard Base64 encoding as well,
        // now we only generate Base64UrlSafe strings (without padding), but
        // we want to accept the old ones as well!
        return rtrim(
            str_replace(
                ['+', '/'],
                ['-', '_'],
                $receivedCodeToken
            ),
            '='
        );
    }
}
