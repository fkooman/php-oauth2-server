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

class RequestValidator
{
    public static function validateAuthorizeQueryParameters(array $getData)
    {
        // REQUIRED
        foreach (['client_id', 'redirect_uri', 'response_type', 'scope', 'state'] as $queryParameter) {
            if (!array_key_exists($queryParameter, $getData)) {
                throw new ValidateException(sprintf('missing "%s" parameter', $queryParameter));
            }
        }

        // NOTE: no need to validate the redirect_uri, as we do strict matching
        SyntaxValidator::validateClientId($getData['client_id']);
        SyntaxValidator::validateResponseType($getData['response_type']);
        SyntaxValidator::validateScope($getData['scope']);
        SyntaxValidator::validateState($getData['state']);

        // OPTIONAL
        if (array_key_exists('code_challenge_method', $getData)) {
            SyntaxValidator::validateCodeChallengeMethod($getData['code_challenge_method']);
        }
        if (array_key_exists('code_challenge', $getData)) {
            SyntaxValidator::validateCodeChallenge($getData['code_challenge']);
        }
    }

    public static function validateAuthorizePostParameters(array $postData)
    {
        if (!array_key_exists('approve', $postData)) {
            throw new ValidateException('missing "approve" parameter');
        }

        SyntaxValidator::validateApprove($postData['approve']);
    }

    public static function validateTokenPostParameters(array $postData)
    {
        // "grant_type" is ALWAYS required
        if (!array_key_exists('grant_type', $postData)) {
            throw new ValidateException('missing "grant_type" parameter');
        }
        SyntaxValidator::validateGrantType($postData['grant_type']);

        switch ($postData['grant_type']) {
            case 'authorization_code':
                self::validateAuthorizationCode($postData);
                break;
            case 'refresh_token':
                self::validateRefreshToken($postData);
                break;
            default:
                throw new ValidateException('invalid "grant_type"');
        }
    }

    public static function validatePkceParameters(array $getData)
    {
        if (!array_key_exists('code_challenge_method', $getData)) {
            throw new ValidateException('missing "code_challenge_method" parameter');
        }
        if (!array_key_exists('code_challenge', $getData)) {
            throw new ValidateException('missing "code_challenge" parameter');
        }
    }

    private static function validateAuthorizationCode(array $postData)
    {
        foreach (['code', 'redirect_uri', 'client_id'] as $postParameter) {
            if (!array_key_exists($postParameter, $postData)) {
                throw new ValidateException(sprintf('missing "%s" parameter', $postParameter));
            }
        }

        // check syntax
        // NOTE: no need to validate the redirect_uri, as we do strict matching
        SyntaxValidator::validateCode($postData['code']);
        SyntaxValidator::validateClientId($postData['client_id']);

        // OPTIONAL
        if (array_key_exists('code_verifier', $postData)) {
            SyntaxValidator::validateCodeVerifier($postData['code_verifier']);
        }
    }

    private static function validateRefreshToken(array $postData)
    {
        foreach (['refresh_token', 'scope'] as $postParameter) {
            if (!array_key_exists($postParameter, $postData)) {
                throw new ValidateException(sprintf('missing "%s" parameter', $postParameter));
            }
        }
        SyntaxValidator::validateRefreshToken($postData['refresh_token']);
        SyntaxValidator::validateScope($postData['scope']);
    }
}
