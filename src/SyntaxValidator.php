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
        if ('code' !== $responseType && 'token' !== $responseType) {
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
