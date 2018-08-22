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

use DateInterval;
use DateTime;
use fkooman\Jwt\RS256;

class OpenId
{
    /** @var string */
    private $tokenIssuer;

    /** @var \fkooman\Jwt\RS256 */
    private $jwtEncoder;

    /** @var \DateTime */
    private $dateTime;

    /** @var \DateInterval */
    private $idTokenExpiry;

    /**
     * @param string             $tokenIssuer
     * @param \fkooman\Jwt\RS256 $jwtEncoder
     */
    public function __construct($tokenIssuer, RS256 $jwtEncoder)
    {
        $this->tokenIssuer = $tokenIssuer;
        $this->jwtEncoder = $jwtEncoder;
        $this->dateTime = new DateTime();
        $this->idTokenExpiry = new DateInterval('PT8H');
    }

    /**
     * @param string $clientId
     * @param string $userId
     *
     * @return string
     */
    public function getIdToken($clientId, $userId)
    {
        $expiresAt = \date_add(clone $this->dateTime, $this->idTokenExpiry);

        return $this->jwtEncoder->encode(
            [
                'iss' => $this->tokenIssuer,
                'sub' => $userId,
                'aud' => $clientId,
                'exp' => $expiresAt->getTimestamp(),
                'iat' => $this->dateTime->getTimestamp(),
                'auth_time' => $this->dateTime->getTimestamp(), // XXX technically not correct, it must be *authentication* time
            ]
        );
    }
}
