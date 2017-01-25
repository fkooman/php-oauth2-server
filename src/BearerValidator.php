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

class BearerValidator
{
    /** @var TokenStorage */
    private $tokenStorage;

    /** @var \DateTime */
    private $dateTime;

    public function __construct(TokenStorage $tokenStorage, DateTime $dateTime)
    {
        $this->tokenStorage = $tokenStorage;
        $this->dateTime = $dateTime;
    }

    /**
     * @param string $bearerToken
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

        if (false === strpos($bearerToken, '.')) {
            throw new BearerException('syntax error (contains no dot)');
        }

        list($accessTokenKey, $accessToken) = explode('.', $bearerToken);
        $tokenInfo = $this->tokenStorage->getToken($accessTokenKey);
        if (false === $tokenInfo) {
            throw new BearerException('token does not exist');
        }

        if (0 !== \Sodium\compare($tokenInfo['access_token'], $accessToken)) {
            throw new BearerException('token does not exist');
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
    }
}
