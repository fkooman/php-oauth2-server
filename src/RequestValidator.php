<?php

/*
 * Copyright (c) 2017, 2018 François Kooman <fkooman@tuxed.net>
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

class RequestValidator
{
    /**
     * @param array<string,string> $getData
     *
     * @return void
     */
    public static function validateAuthorizeQueryParameters(array $getData)
    {
        // REQUIRED
        foreach (['client_id', 'redirect_uri', 'response_type', 'scope', 'state'] as $queryParameter) {
            if (!\array_key_exists($queryParameter, $getData)) {
                throw new InvalidRequestException(\sprintf('missing "%s" parameter', $queryParameter));
            }
        }

        // NOTE: no need to validate the redirect_uri, as we do strict matching
        SyntaxValidator::validateClientId($getData['client_id']);
        SyntaxValidator::validateResponseType($getData['response_type']);
        SyntaxValidator::validateScope($getData['scope']);
        SyntaxValidator::validateState($getData['state']);

        // OPTIONAL
        if (\array_key_exists('code_challenge_method', $getData)) {
            SyntaxValidator::validateCodeChallengeMethod($getData['code_challenge_method']);
        }
        if (\array_key_exists('code_challenge', $getData)) {
            SyntaxValidator::validateCodeChallenge($getData['code_challenge']);
        }
    }

    /**
     * @param array<string,string> $postData
     *
     * @return void
     */
    public static function validateAuthorizePostParameters(array $postData)
    {
        if (!\array_key_exists('approve', $postData)) {
            throw new InvalidRequestException('missing "approve" parameter');
        }

        SyntaxValidator::validateApprove($postData['approve']);
    }

    /**
     * @param array<string,string> $postData
     *
     * @return void
     */
    public static function validateTokenPostParameters(array $postData)
    {
        // "grant_type" is ALWAYS required
        if (!\array_key_exists('grant_type', $postData)) {
            throw new InvalidRequestException('missing "grant_type" parameter');
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
                throw new InvalidRequestException('invalid "grant_type"');
        }
    }

    /**
     * @param array<string,string> $getData
     *
     * @return void
     */
    public static function validatePkceParameters(array $getData)
    {
        if (!\array_key_exists('code_challenge_method', $getData)) {
            throw new InvalidRequestException('missing "code_challenge_method" parameter');
        }
        if (!\array_key_exists('code_challenge', $getData)) {
            throw new InvalidRequestException('missing "code_challenge" parameter');
        }
    }

    /**
     * @param array<string,string> $postData
     *
     * @return void
     */
    private static function validateAuthorizationCode(array $postData)
    {
        foreach (['code', 'redirect_uri', 'client_id'] as $postParameter) {
            if (!\array_key_exists($postParameter, $postData)) {
                throw new InvalidRequestException(\sprintf('missing "%s" parameter', $postParameter));
            }
        }

        // NOTE: no need to validate the redirect_uri, as we do strict matching
        SyntaxValidator::validateCode($postData['code']);
        SyntaxValidator::validateClientId($postData['client_id']);

        // OPTIONAL
        if (\array_key_exists('code_verifier', $postData)) {
            SyntaxValidator::validateCodeVerifier($postData['code_verifier']);
        }
    }

    /**
     * @param array<string,string> $postData
     *
     * @return void
     */
    private static function validateRefreshToken(array $postData)
    {
        foreach (['refresh_token'] as $postParameter) {
            if (!\array_key_exists($postParameter, $postData)) {
                throw new InvalidRequestException(\sprintf('missing "%s" parameter', $postParameter));
            }
        }
        SyntaxValidator::validateRefreshToken($postData['refresh_token']);

        // OPTIONAL
        if (\array_key_exists('scope', $postData)) {
            SyntaxValidator::validateScope($postData['scope']);
        }
    }
}
