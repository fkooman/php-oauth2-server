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

use DateTime;
use fkooman\OAuth\Server\Exception\InvalidGrantException;
use fkooman\OAuth\Server\Exception\ServerErrorException;
use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Base64UrlSafe;

class LegacyTokenSigner implements TokenSignerInterface
{
    /** @var string */
    private $keyPair;

    /** @var \DateTime */
    private $dateTime;

    /**
     * @param string $keyPair
     */
    public function __construct($keyPair)
    {
        $this->keyPair = Base64::decode($keyPair);
        $this->dateTime = new DateTime();
    }

    /**
     * @param array     $listOfClaims
     * @param \DateTime $expiresAt
     *
     * @throws \fkooman\OAuth\Server\Exception\InvalidGrantException
     *
     * @return string
     */
    public function sign(array $listOfClaims, DateTime $expiresAt)
    {
        $listOfClaims['expires_at'] = $expiresAt->format('Y-m-d H:i:s');

        $jsonString = json_encode($listOfClaims);
        if (false === $jsonString) {
            throw new ServerErrorException('unable to encode JSON');
        }

        return rtrim(
            Base64UrlSafe::encode(
                sodium_crypto_sign(
                    $jsonString,
                    sodium_crypto_sign_secretkey($this->keyPair)
                )
            ),
            '='
        );
    }

    /**
     * @param string $providedToken
     *
     * @throws \fkooman\OAuth\Server\Exception\InvalidGrantException
     *
     * @return array
     */
    public function parse($providedToken)
    {
        // support old Base64 encoded strings as well...
        $encodedSignedStr = str_replace(['+', '/'], ['-', '_'], $providedToken);
        $signedStr = Base64UrlSafe::decode($encodedSignedStr);
        $str = sodium_crypto_sign_open($signedStr, sodium_crypto_sign_publickey($this->keyPair));
        if (false === $str) {
            throw new InvalidGrantException('invalid signature');
        }
        $codeTokenInfo = json_decode($str, true);
        if (null === $codeTokenInfo && JSON_ERROR_NONE !== json_last_error()) {
            throw new ServerErrorException('unable to decode JSON');
        }

        // check expiry
        if (array_key_exists('expires_at', $codeTokenInfo)) {
            // versions of fkooman/oauth2-server < 2.2.0 did not have expiring
            // refresh tokens, we accept those without verifying the expiry
            if ($this->dateTime >= new DateTime($codeTokenInfo['expires_at'])) {
                throw new InvalidGrantException('code or token expired');
            }
        }

//        // check for token expiry if `expires_at` is set
//        // XXX but maybe expires_at is not set, then we ignore it!
//        if ($this->dateTime >= new DateTime($codeTokenInfo['expires_at'])) {
//            throw new InvalidGrantException('token expired');
//        }

        return $codeTokenInfo;
    }
}
