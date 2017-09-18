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
use InvalidArgumentException;
use ParagonIE\ConstantTime\Base64;
use RangeException;

class BearerValidator
{
    /** @var Storage */
    private $storage;

    /** @var string */
    private $publicKey;

    /** @var array */
    private $foreignKeys = [];

    /** @var \DateTime */
    private $dateTime;

    /**
     * @param Storage $storage
     * @param string  $keyPair the Base64 encoded keyPair
     */
    public function __construct(Storage $storage, $keyPair)
    {
        $this->storage = $storage;
        $this->publicKey = SodiumCompat::crypto_sign_publickey(Base64::decode($keyPair));
        $this->dateTime = new DateTime();
    }

    /**
     * @param DateTime $dateTime
     *
     * @return void
     */
    public function setDateTime(DateTime $dateTime)
    {
        $this->dateTime = $dateTime;
    }

    /**
     * Set additional public keys to use for access_token validation. These are
     * _NOT_ validated in the database.
     *
     * @param array $foreignKeys the Base64 encoded public key(s)
     *
     * @return void
     */
    public function setForeignKeys(array $foreignKeys)
    {
        $this->foreignKeys = [];
        foreach ($foreignKeys as $tokenIssuer => $publicKey) {
            if (!is_string($tokenIssuer)) {
                throw new InvalidArgumentException('tokenIssuer MUST be string');
            }
            $this->foreignKeys[$tokenIssuer] = Base64::decode($publicKey);
        }
    }

    /**
     * @param string $authorizationHeader
     *
     * @return TokenInfo
     */
    public function validate($authorizationHeader)
    {
        self::validateBearerCredentials($authorizationHeader);
        try {
            $bearerToken = substr($authorizationHeader, 7);
            $signedBearerToken = Base64::decode($bearerToken);

            // make sure access_token is signed by us
            if (false !== $jsonToken = SodiumCompat::crypto_sign_open($signedBearerToken, $this->publicKey)) {
                // as it is signed by us, it MUST exist in the DB as well,
                // otherwise it was revoked...
                $tokenInfo = $this->validateTokenInfo(json_decode($jsonToken, true));
                if (!$this->storage->hasAuthorization($tokenInfo->getAuthKey())) {
                    throw new BearerException('authorization no longer exists, invalid token');
                }

                return $tokenInfo;
            }

            // it was not our signature, maybe it is one of the OPTIONAL
            // additionally configured public keys
            foreach ($this->foreignKeys as $tokenIssuer => $publicKey) {
                if (false !== $jsonToken = SodiumCompat::crypto_sign_open($signedBearerToken, $publicKey)) {
                    $tokenInfo = $this->validateTokenInfo(json_decode($jsonToken, true));
                    $tokenInfo->setIssuer($tokenIssuer);

                    return $tokenInfo;
                }
            }

            // non of the additional public keys (if they were set) were able
            // to validate the token
            throw new BearerException('invalid signature');
        } catch (RangeException $e) {
            // Base64::decode throws this exception if string is not valid Base64
            throw new BearerException('invalid token format');
        }
    }

    /**
     * @param array $tokenInfo
     *
     * @return TokenInfo
     */
    private function validateTokenInfo(array $tokenInfo)
    {
        // type MUST be "access_token"
        if ('access_token' !== $tokenInfo['type']) {
            throw new BearerException('not an access token');
        }

        $expiresAt = new DateTime($tokenInfo['expires_at']);
        if ($this->dateTime >= $expiresAt) {
            throw new BearerException('token expired');
        }

        return new TokenInfo(
            $tokenInfo['auth_key'],
            $tokenInfo['user_id'],
            $tokenInfo['scope'],
            $expiresAt
        );
    }

    /**
     * @param string $bearerCredentials
     *
     * @return void
     */
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
