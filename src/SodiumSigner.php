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
use fkooman\OAuth\Server\Exception\SignerException;
use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Base64UrlSafe;
use RangeException;

class SodiumSigner implements SignerInterface
{
    /** @var string */
    private $secretKey;

    /** @var string */
    private $publicKey;

    /**
     * @param string $keyPair
     */
    public function __construct($keyPair)
    {
        if (SODIUM_CRYPTO_SIGN_KEYPAIRBYTES !== strlen($keyPair)) {
            throw new ServerErrorException('invalid keypair');
        }
        $this->secretKey = sodium_crypto_sign_secretkey($keyPair);
        $this->publicKey = sodium_crypto_sign_publickey($keyPair);
    }

    /**
     * @param array $listOfClaims
     *
     * @throws Exception\SignerException
     *
     * @return string
     */
    public function sign(array $listOfClaims)
    {
        $jsonString = json_encode($listOfClaims);
        if (false === $jsonString && JSON_ERROR_NONE !== json_last_error()) {
            throw new SignerException('unable to encode JSON');
        }

        // Base64UrlSafe without padding
        return rtrim(
            Base64UrlSafe::encode(
                sodium_crypto_sign($jsonString, $this->secretKey)
            ),
            '='
        );
    }

    /**
     * @param string $inputTokenStr
     *
     * @throws Exception\SignerException
     *
     * @return array
     */
    public function verify($inputTokenStr)
    {
        try {
            $decodedTokenStr = self::decodeBase64(
                self::normalize($inputTokenStr)
            );

            if (false === $jsonString = sodium_crypto_sign_open($decodedTokenStr, $this->publicKey)) {
                throw new SignerException('invalid signature');
            }

            $listOfClaims = json_decode($jsonString, true);
            if (null === $listOfClaims && JSON_ERROR_NONE !== json_last_error()) {
                throw new SignerException('unable to decode JSON');
            }

            return $listOfClaims;
        } catch (RangeException $e) {
            throw new SignerException('unable to decode Base64');
        }
    }

    /**
     * @param string $inputStr
     *
     * @return string
     */
    private static function decodeBase64($inputStr)
    {
        // Base64UrlSafe decode
        if (false === $outputStr = Base64UrlSafe::decode($inputStr)) {
            // paragonie/constant_time_encoding v1.0.1 sometimes returns
            // false when decoding fails, so handle this here as well
            // https://github.com/paragonie/constant_time_encoding/issues/14
            throw new RangeException('Base64::decode() only expects characters in the correct base64 alphabet');
        }

        return $outputStr;
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
