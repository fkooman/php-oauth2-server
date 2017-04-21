<?php

/**
 * Copyright (c) 2017 François Kooman <fkooman@tuxed.net>.
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
use fkooman\OAuth\Server\Exception\BearerException;
use ParagonIE\ConstantTime\Base64;
use RangeException;

/**
 * Use this class if you want to validate Bearer tokens on a different machine
 * as the OAuth Server.
 */
class BearerValidator
{
    /** @var \DateTime */
    private $dateTime;

    /** @var array */
    private $publicKeys;

    /**
     * @param array          $publicKeys
     * @param \DateTime|null $dateTime
     */
    public function __construct(array $publicKeys, DateTime $dateTime = null)
    {
        $this->publicKeys = $publicKeys;
        if (is_null($dateTime)) {
            $dateTime = new DateTime();
        }
        $this->dateTime = $dateTime;
    }

    /**
     * @param string $authorizationHeader
     *
     * @return array
     */
    public function validate($authorizationHeader)
    {
        self::validateBearerCredentials($authorizationHeader);
        try {
            $bearerToken = substr($authorizationHeader, 7);
            $signedBearerToken = Base64::decode($bearerToken);
            $jsonToken = $this->tryPublicKeys($signedBearerToken);
            $tokenInfo = json_decode($jsonToken, true);

            // type MUST be "access_token"
            if ('access_token' !== $tokenInfo['type']) {
                throw new BearerException('not an access token');
            }

            $expiresAt = new DateTime($tokenInfo['expires_at']);
            if ($this->dateTime >= $expiresAt) {
                throw new BearerException('token expired');
            }

            return [
                'auth_key' => $tokenInfo['auth_key'],
                'user_id' => $tokenInfo['user_id'],
                'scope' => $tokenInfo['scope'],
                'expires_in' => $expiresAt->getTimestamp() - $this->dateTime->getTimestamp(),
            ];
        } catch (RangeException $e) {
            // Base64::decode throws this exception if string is not valid Base64
            throw new BearerException('invalid token format');
        }
    }

    private function tryPublicKeys($signedBearerToken)
    {
        foreach ($this->publicKeys as $publicKey) {
            if (false !== $jsonToken = \Sodium\crypto_sign_open($signedBearerToken, Base64::decode($publicKey))) {
                return $jsonToken;
            }
        }

        throw new BearerException('invalid signature');
    }

    private static function validateBearerCredentials($bearerCredentials)
    {
        // b64token    = 1*( ALPHA / DIGIT /
        //                   "-" / "." / "_" / "~" / "+" / "/" ) *"="
        // credentials = "Bearer" 1*SP b64token
        if (1 !== preg_match('|^Bearer [a-zA-Z0-9-._~+/]+=*$|', $bearerCredentials)) {
            throw new BearerException('bearer credential syntax error');
        }
    }
}
