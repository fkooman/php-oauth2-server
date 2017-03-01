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
            if (false !== $jsonToken = \Sodium\crypto_sign_open($signedBearerToken, $publicKey)) {
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
