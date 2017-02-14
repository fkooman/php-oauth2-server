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
    /** @var Storage */
    private $storage;

    /** @var \DateTime */
    private $dateTime;

    /** @var string */
    private $signPublicKey;

    public function __construct(Storage $storage, $signPublicKey, DateTime $dateTime = null)
    {
        $this->storage = $storage;
        $this->signPublicKey = $signPublicKey;
        if (is_null($dateTime)) {
            $dateTime = new DateTime();
        }
        $this->dateTime = $dateTime;
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
            if (false === $plainText = \Sodium\crypto_sign_open(Base64::decode($bearerToken), $this->signPublicKey)) {
                throw new BearerException('invalid signature');
            }

            $jsonData = json_decode($plainText, true);
            $expiresAt = new DateTime($jsonData['expires_at']);

            if ($this->dateTime >= $expiresAt) {
                throw new BearerException('token expired');
            }

            return [
                'user_id' => $jsonData['user_id'],
                'scope' => $jsonData['scope'],
                'expires_in' => $expiresAt->getTimestamp() - $this->dateTime->getTimestamp(),
            ];
        } catch (RangeException $e) {
            // Base64::decode throws this exception if string is not valid Base64
            throw new BearerException('invalid token format');
        }
    }
}
