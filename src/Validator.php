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
use fkooman\OAuth\Server\Exception\OAuthException;

class Validator
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
     * @param string|null $authorizationHeader
     *
     * @return array with "user_id" and "scope" fields
     */
    public function validate($authorizationHeader)
    {
        if (is_null($authorizationHeader)) {
            throw new OAuthException('no_token', 'no authorization header', 401);
        }

        // b64token    = 1*( ALPHA / DIGIT /
        //                   "-" / "." / "_" / "~" / "+" / "/" ) *"="
        // credentials = "Bearer" 1*SP b64token
        if (1 !== preg_match('|^Bearer [a-zA-Z0-9-._~+/]+=*$|', $authorizationHeader)) {
            throw new OAuthException('no_token', 'no Bearer token', 401);
        }

        $bearerToken = substr($authorizationHeader, 7);
        if (false === strpos($bearerToken, '.')) {
            throw new OAuthException('invalid_token', 'bearer token is expected to contain a "."', 401);
        }

        list($accessTokenKey, $accessToken) = explode('.', $bearerToken);
        $tokenInfo = $this->tokenStorage->getToken($accessTokenKey);
        if (false === $tokenInfo) {
            throw new OAuthException('invalid_token', 'token key does not exist', 401);
        }

        // time safe string compare, using polyfill on PHP < 5.6
        if (0 !== \Sodium\compare($tokenInfo['access_token'], $accessToken)) {
            throw new OAuthException('invalid_token', 'token does not match expected value', 401);
        }

        $expiresAt = new DateTime($tokenInfo['expires_at']);
        if ($this->dateTime > $expiresAt) {
            throw new OAuthException('invalid_token', 'token expired', 401);
        }

        return [
            'user_id' => $tokenInfo['user_id'],
            'scope' => $tokenInfo['scope'],
        ];
    }
}
