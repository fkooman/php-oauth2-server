<?php
/**
 *  Copyright (C) 2017 François Kooman <fkooman@tuxed.net>.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as
 *  published by the Free Software Foundation, either version 3 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

namespace fkooman\OAuth\Server;

use DateTime;
use fkooman\OAuth\Server\Exception\BearerException;
use ParagonIE\ConstantTime\Base64;
use RangeException;

class BearerValidator
{
    /** @var string */
    private $keyPair;

    /** @var Storage */
    private $storage;

    /** @var \DateTime */
    private $dateTime;

    /** @var array */
    private $publicKeys = [];

    public function __construct($keyPair, Storage $storage, DateTime $dateTime = null)
    {
        $this->keyPair = $keyPair;
        $this->storage = $storage;
        if (is_null($dateTime)) {
            $dateTime = new DateTime();
        }
        $this->dateTime = $dateTime;
    }

    /**
     * @param string $publicKey
     */
    public function addPublicKey($publicKey)
    {
        $this->publicKeys[] = $publicKey;
    }

    /**
     * @param string $authorizationHeader
     *
     * @return false|array
     *
     * @throws BearerException when the provided Bearer token is not valid
     */
    public function validate($authorizationHeader)
    {
        if (0 !== strpos($authorizationHeader, 'Bearer ')) {
            return false;
        }
        $bearerToken = substr($authorizationHeader, 7);

        // b64token    = 1*( ALPHA / DIGIT /
        //                   "-" / "." / "_" / "~" / "+" / "/" ) *"="
        // credentials = "Bearer" 1*SP b64token
        if (1 !== preg_match('|^[a-zA-Z0-9-._~+/]+=*$|', $bearerToken)) {
            throw new BearerException('syntax error');
        }

        return $this->validateSignedToken($bearerToken);
    }

    /**
     * @param string $bearerToken
     */
    private function validateSignedToken($bearerToken)
    {
        try {
            $signedToken = Base64::decode($bearerToken);

            // try to verify the token with the publicKey from the keyPair
            $publicKey = \Sodium\crypto_sign_publickey($this->keyPair);
            $isLocalToken = true;
            if (false === $jsonToken = \Sodium\crypto_sign_open($signedToken, $publicKey)) {
                // we were unable to verify the signature with our own keyPair,
                // attempt with additional publicKeys if they are set
                $jsonToken = $this->verifyWithPublicKeys($signedToken);
                $isLocalToken = false;
            }

            $tokenInfo = json_decode($jsonToken, true);
            // type MUST be "access_token"
            if ('access_token' !== $tokenInfo['type']) {
                throw new BearerException('not an access token');
            }

            $expiresAt = new DateTime($tokenInfo['expires_at']);
            if ($this->dateTime >= $expiresAt) {
                throw new BearerException('token expired');
            }

            if ($isLocalToken) {
                // if we signed this token ourselves, we also check if there
                // (still) is an authorization in the DB to make sure that
                // when a user "revokes" the authorization, access tokens are
                // no longer valid immediately, instead of waiting for the
                // access token to expire
                if (!$this->storage->hasAuthorization($tokenInfo['auth_key'])) {
                    // authorization does not exist (any longer)
                    throw new BearerException('invalid token');
                }
            }

            return [
                'user_id' => $tokenInfo['user_id'],
                'scope' => $tokenInfo['scope'],
                'expires_in' => $expiresAt->getTimestamp() - $this->dateTime->getTimestamp(),
            ];
        } catch (RangeException $e) {
            // Base64::decode throws this exception if string is not valid Base64
            throw new BearerException('invalid token format');
        }
    }

    private function verifyWithPublicKeys($signedToken)
    {
        foreach ($this->publicKeys as $publicKey) {
            if (false !== $jsonToken = \Sodium\crypto_sign_open($signedToken, $publicKey)) {
                return $jsonToken;
            }
        }

        throw new BearerException('invalid signature');
    }
}
