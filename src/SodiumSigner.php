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

use fkooman\OAuth\Server\Exception\InvalidRequestException;
use fkooman\OAuth\Server\Exception\ServerErrorException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use RangeException;

class SodiumSigner implements SignerInterface
{
    /** @var string */
    private $secretKey;

    /** @var array */
    private $publicKeyList = [];

    /**
     * @param string $keyPair
     * @param array  $publicKeyList
     */
    public function __construct($keyPair, array $publicKeyList = [])
    {
        if (SODIUM_CRYPTO_SIGN_KEYPAIRBYTES !== Binary::safeStrlen($keyPair)) {
            throw new ServerErrorException('invalid keypair length');
        }
        $this->secretKey = sodium_crypto_sign_secretkey($keyPair);
        $this->publicKeyList['local'] = sodium_crypto_sign_publickey($keyPair);

        foreach ($publicKeyList as $keyId => $publicKey) {
            if (!is_string($keyId) || 0 >= Binary::safeStrlen($keyId) || 'local' === $keyId) {
                throw new ServerErrorException('keyId MUST be non-empty string != "local"');
            }
            if (SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== Binary::safeStrlen($publicKey)) {
                throw new ServerErrorException(sprintf('invalid public key length for key "%s"', $keyId));
            }
            $this->publicKeyList[$keyId] = $publicKey;
        }
    }

    /**
     * @param array $listOfClaims
     *
     * @return string
     */
    public function sign(array $listOfClaims)
    {
        $jsonString = json_encode($listOfClaims);
        if (false === $jsonString && JSON_ERROR_NONE !== json_last_error()) {
            throw new ServerErrorException('unable to encode JSON');
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
     * @return false|array
     */
    public function verify($inputTokenStr)
    {
        try {
            $decodedTokenStr = Base64UrlSafe::decode(
                self::normalize($inputTokenStr)
            );

            foreach ($this->publicKeyList as $keyId => $publicKey) {
                if (false !== $jsonString = sodium_crypto_sign_open($decodedTokenStr, $publicKey)) {
                    $listOfClaims = json_decode($jsonString, true);
                    if (null === $listOfClaims && JSON_ERROR_NONE !== json_last_error()) {
                        // this should NEVER happen, as we encode the JSON, so we
                        // should also be able to parse it!
                        throw new ServerErrorException('unable to decode JSON');
                    }
                    $listOfClaims['key_id'] = $keyId;

                    return $listOfClaims;
                }
            }

            return false;
        } catch (RangeException $e) {
            // this indicates the provided Base64 encoded token is malformed,
            // this is an "user" error!
            throw new InvalidRequestException('unable to decode Base64');
        }
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
