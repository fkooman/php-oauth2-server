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

use fkooman\OAuth\Server\Exception\ValidateException;

class SyntaxValidator
{
    /**
     * @param string $clientId
     */
    public static function validateClientId($clientId)
    {
        // client-id  = *VSCHAR
        // VSCHAR     = %x20-7E
        if (1 !== preg_match('/^[\x20-\x7E]+$/', $clientId)) {
            throw new ValidateException('invalid "client_id"');
        }
    }

    /**
     * Validate the authorization code.
     *
     * @param string $code
     */
    public static function validateCode($code)
    {
        // code       = 1*VSCHAR
        // VSCHAR     = %x20-7E
        if (1 !== preg_match('/^[\x20-\x7E]+$/', $code)) {
            throw new ValidateException('invalid "code"');
        }
    }

    /**
     * @param string $grantType
     */
    public static function validateGrantType($grantType)
    {
        // grant-type = grant-name / URI-reference
        // grant-name = 1*name-char
        // name-char  = "-" / "." / "_" / DIGIT / ALPHA

        // we have an explicit whitelist here
        if ('authorization_code' !== $grantType && 'refresh_token' !== $grantType) {
            throw new ValidateException('invalid "grant_type"');
        }
    }

    /**
     * @param string $responseType
     */
    public static function validateResponseType($responseType)
    {
        if ('code' !== $responseType) {
            throw new ValidateException('invalid "response_type"');
        }
    }

    /**
     * @param string $scope
     */
    public static function validateScope($scope)
    {
        // scope       = scope-token *( SP scope-token )
        // scope-token = 1*NQCHAR
        // NQCHAR      = %x21 / %x23-5B / %x5D-7E
        foreach (explode(' ', $scope) as $scopeToken) {
            if (1 !== preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+$/', $scopeToken)) {
                throw new ValidateException('invalid "scope"');
            }
        }
    }

    /**
     * @param string $state
     */
    public static function validateState($state)
    {
        // state      = 1*VSCHAR
        // VSCHAR     = %x20-7E
        if (1 !== preg_match('/^[\x20-\x7E]+$/', $state)) {
            throw new ValidateException('invalid "state"');
        }
    }

    /**
     * @param string $codeChallengeMethod
     */
    public static function validateCodeChallengeMethod($codeChallengeMethod)
    {
        if ('S256' !== $codeChallengeMethod) {
            throw new ValidateException('invalid "code_challenge_method"');
        }
    }

    /**
     * @param string $codeVerifier
     */
    public static function validateCodeVerifier($codeVerifier)
    {
        // code-verifier = 43*128unreserved
        // unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
        // ALPHA         = %x41-5A / %x61-7A
        // DIGIT         = %x30-39
        if (1 !== preg_match('/^[\x41-\x5A\x61-\x7A\x30-\x39-._~]{43,128}$/', $codeVerifier)) {
            throw new ValidateException('invalid "code_verifier"');
        }
    }

    /**
     * @param string $codeChallenge
     */
    public static function validateCodeChallenge($codeChallenge)
    {
        // it seems the length of the codeChallenge is always 43 because it is
        // the output of the SHA256 hashing algorithm
        if (1 !== preg_match('/^[\x41-\x5A\x61-\x7A\x30-\x39-_]{43}$/', $codeChallenge)) {
            throw new ValidateException('invalid "code_challenge"');
        }
    }

    /**
     * @param string $approve
     */
    public static function validateApprove($approve)
    {
        if (!in_array($approve, ['yes', 'no'])) {
            throw new ValidateException('invalid "approve"');
        }
    }

    /**
     * @param string $refreshToken
     */
    public static function validateRefreshToken($refreshToken)
    {
        // refresh-token = 1*VSCHAR
        // VSCHAR        = %x20-7E
        if (1 !== preg_match('/^[\x20-\x7E]+$/', $refreshToken)) {
            throw new ValidateException('invalid "refresh_token"');
        }
    }
}
