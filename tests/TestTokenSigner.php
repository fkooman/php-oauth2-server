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

use DateTime;
use fkooman\OAuth\Server\Exception\InvalidGrantException;
use fkooman\OAuth\Server\Exception\InvalidTokenException;
use fkooman\OAuth\Server\TokenSignerInterface;
use ParagonIE\ConstantTime\Base64UrlSafe;

class TestTokenSigner implements TokenSignerInterface
{
    /** @var \DateTime */
    private $dateTime;

    public function __construct(DateTime $dateTime)
    {
        $this->dateTime = $dateTime;
    }

    /**
     * @param array     $listOfClaims
     * @param \DateTime $expiresAt
     *
     * @return string
     */
    public function sign(array $listOfClaims, DateTime $expiresAt)
    {
        $listOfClaims['expires_at'] = $expiresAt->format('Y-m-d H:i:s');

        return rtrim(
            Base64UrlSafe::encode(
                json_encode($listOfClaims)
            ),
            '='
        );
    }

    /**
     * @param string $providedToken
     * @param string $requireType
     *
     * @throws \fkooman\OAuth\Server\Exception\InvalidGrantException|\fkooman\OAuth\Server\Exception\InvalidTokenException
     *
     * @return array
     */
    public function parse($providedToken, $requireType)
    {
        $parsedToken = json_decode(
            Base64UrlSafe::decode($providedToken),
            true
        );

        // verify it is not expired
        if (array_key_exists('expires_at', $parsedToken)) {
            // versions of fkooman/oauth2-server < 2.2.0 did not have expiring
            // refresh tokens, we accept those without verifying the expiry
            if ($this->dateTime >= new DateTime($parsedToken['expires_at'])) {
                if ('access_token' === $requireType) {
                    throw new InvalidTokenException('"access_token" expired');
                }

                throw new InvalidGrantException(sprintf('"%s" expired', $requireType));
            }
        }

        return $parsedToken;
    }
}
