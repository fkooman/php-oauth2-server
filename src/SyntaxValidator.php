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

use fkooman\OAuth\Server\Exception\InvalidRequestException;
use fkooman\OAuth\Server\Exception\InvalidScopeException;
use fkooman\OAuth\Server\Exception\UnsupportedResponseTypeException;

class SyntaxValidator
{
    /**
     * @param string $clientId
     *
     * @return void
     */
    public static function validateClientId($clientId)
    {
        // client-id  = *VSCHAR
        // VSCHAR     = %x20-7E
        if (1 !== preg_match('/^[\x20-\x7E]+$/', $clientId)) {
            throw new InvalidRequestException('invalid "client_id"');
        }
    }

    /**
     * Validate the authorization code.
     *
     * @param string $code
     *
     * @return void
     */
    public static function validateCode($code)
    {
        // code       = 1*VSCHAR
        // VSCHAR     = %x20-7E
        if (1 !== preg_match('/^[\x20-\x7E]+$/', $code)) {
            throw new InvalidRequestException('invalid "code"');
        }
    }

    /**
     * @param string $grantType
     *
     * @return void
     */
    public static function validateGrantType($grantType)
    {
        // grant-type = grant-name / URI-reference
        // grant-name = 1*name-char
        // name-char  = "-" / "." / "_" / DIGIT / ALPHA

        // we have an explicit whitelist here
        if ('authorization_code' !== $grantType && 'refresh_token' !== $grantType) {
            throw new InvalidRequestException('invalid "grant_type"');
        }
    }

    /**
     * @param string $responseType
     *
     * @return void
     */
    public static function validateResponseType($responseType)
    {
        if ('code' !== $responseType) {
            throw new UnsupportedResponseTypeException('unsupported "response_type"');
        }
    }

    /**
     * @param string $scope
     *
     * @return void
     */
    public static function validateScope($scope)
    {
        // scope       = scope-token *( SP scope-token )
        // scope-token = 1*NQCHAR
        // NQCHAR      = %x21 / %x23-5B / %x5D-7E
        foreach (explode(' ', $scope) as $scopeToken) {
            if (1 !== preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+$/', $scopeToken)) {
                throw new InvalidScopeException('invalid "scope"');
            }
        }
    }

    /**
     * @param string $state
     *
     * @return void
     */
    public static function validateState($state)
    {
        // state      = 1*VSCHAR
        // VSCHAR     = %x20-7E
        if (1 !== preg_match('/^[\x20-\x7E]+$/', $state)) {
            throw new InvalidRequestException('invalid "state"');
        }
    }

    /**
     * @param string $codeChallengeMethod
     *
     * @return void
     */
    public static function validateCodeChallengeMethod($codeChallengeMethod)
    {
        if ('S256' !== $codeChallengeMethod) {
            throw new InvalidRequestException('invalid "code_challenge_method"');
        }
    }

    /**
     * @param string $codeVerifier
     *
     * @return void
     */
    public static function validateCodeVerifier($codeVerifier)
    {
        // code-verifier = 43*128unreserved
        // unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
        // ALPHA         = %x41-5A / %x61-7A
        // DIGIT         = %x30-39
        if (1 !== preg_match('/^[\x41-\x5A\x61-\x7A\x30-\x39-._~]{43,128}$/', $codeVerifier)) {
            throw new InvalidRequestException('invalid "code_verifier"');
        }
    }

    /**
     * @param string $codeChallenge
     *
     * @return void
     */
    public static function validateCodeChallenge($codeChallenge)
    {
        // it seems the length of the codeChallenge is always 43 because it is
        // the output of the SHA256 hashing algorithm
        if (1 !== preg_match('/^[\x41-\x5A\x61-\x7A\x30-\x39-_]{43}$/', $codeChallenge)) {
            throw new InvalidRequestException('invalid "code_challenge"');
        }
    }

    /**
     * @param string $approve
     *
     * @return void
     */
    public static function validateApprove($approve)
    {
        if (!in_array($approve, ['yes', 'no'], true)) {
            throw new InvalidRequestException('invalid "approve"');
        }
    }

    /**
     * @param string $refreshToken
     *
     * @return void
     */
    public static function validateRefreshToken($refreshToken)
    {
        // refresh-token = 1*VSCHAR
        // VSCHAR        = %x20-7E
        if (1 !== preg_match('/^[\x20-\x7E]+$/', $refreshToken)) {
            throw new InvalidRequestException('invalid "refresh_token"');
        }
    }
}
