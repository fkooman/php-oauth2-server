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

use DateInterval;
use DateTime;
use fkooman\OAuth\Server\Exception\TokenException;
use fkooman\OAuth\Server\Exception\ValidateException;

class OAuthServer
{
    /** @var int */
    private $expiresIn = 3600;

    /** @var TokenStorage */
    private $tokenStorage;

    /** @var RandomInterface */
    private $random;

    /** @var \DateTime */
    private $dateTime;

    /** @var callable */
    private $getClientInfo;

    public function __construct(TokenStorage $tokenStorage, RandomInterface $random, DateTime $dateTime, callable $getClientInfo)
    {
        $this->tokenStorage = $tokenStorage;
        $this->random = $random;
        $this->dateTime = $dateTime;
        $this->getClientInfo = $getClientInfo;
    }

    public function setExpiresIn($expiresIn)
    {
        $this->expiresIn = (int) $expiresIn;
    }

    /**
     * Validates the request from the client and returns verified data to
     * show an authorization dialog.
     *
     * @return array
     */
    public function getAuthorize(array $getData)
    {
        $this->validateQueryParameters($getData);
        $clientInfo = $this->validateClient($getData['client_id'], $getData['response_type'], $getData['redirect_uri']);

        return [
            'client_id' => $getData['client_id'],
            'display_name' => $clientInfo['display_name'],
            'scope' => $getData['scope'],
            'redirect_uri' => $getData['redirect_uri'],
        ];
    }

    /**
     * @return string the redirect_uri
     */
    public function postAuthorize(array $getData, array $postData, $userId)
    {
        $this->validateQueryParameters($getData);
        $this->validateClient($getData['client_id'], $getData['response_type'], $getData['redirect_uri']);
        $this->validatePostParameters($postData);

        switch ($getData['response_type']) {
            case 'token':
                return $this->tokenAuthorize($getData, $postData, $userId);
            case 'code':
                return $this->codeAuthorize($getData, $postData, $userId);
            default:
                // can never happen (famous last words...)
                throw new ValidateException('invalid "response_type"', 400);
        }
    }

    /**
     * @return TokenResponse
     *
     * @throws TokenException
     */
    public function postToken(array $postData)
    {
        try {
            $this->validateTokenPostParameters($postData);
            $this->validateClient($postData['client_id'], 'code', $postData['redirect_uri']);
        } catch (ValidateException $e) {
            throw new TokenException('invalid_request', $e->getMessage(), 400);
        }

        list($authorizationCodeKey, $authorizationCode) = explode('.', $postData['code']);

        if (false === $codeInfo = $this->tokenStorage->getCode($authorizationCodeKey)) {
            throw new TokenException('invalid_grant', '"authorization_code" not found', 400);
        }

        if (!hash_equals($codeInfo['authorization_code'], $authorizationCode)) {
            throw new TokenException('invalid_grant', 'invalid "authorization_code"', 400);
        }

        $this->verifyCodeVerifier($codeInfo['code_challenge'], $postData['code_verifier']);

        // check for code expiry, it may be at most 10 minutes old
        $codeTime = new DateTime($codeInfo['issued_at']);
        $codeTime->add(new DateInterval('PT10M'));
        if ($this->dateTime >= $codeTime) {
            throw new TokenException('invalid_grant', 'expired "authorization_code"', 400);
        }

        $this->matchParameters($postData, $codeInfo);

        // check if this authorization code was already used for getting an
        // access_token before...
        if (false !== $this->tokenStorage->getToken($authorizationCodeKey)) {
            // XXX delete all tokens/codes bound to this authorizationCodeKey
            throw new TokenException('invalid_grant', '"authorization_code" already used', 400);
        }

        $accessToken = $this->getAccessToken(
            $codeInfo['user_id'],
            $postData['client_id'],
            $codeInfo['scope'],
            $authorizationCodeKey
        );

        return new TokenResponse(
            [
                'access_token' => $accessToken['access_token'],
                'token_type' => 'bearer',
                'expires_in' => $accessToken['expires_in'],
            ]
        );
    }

    private function matchParameters(array $postData, array $codeInfo)
    {
        if ($postData['client_id'] !== $codeInfo['client_id']) {
            throw new TokenException('invalid_request', 'unexpected "client_id"', 400);
        }

        if ($postData['redirect_uri'] !== $codeInfo['redirect_uri']) {
            throw new TokenException('invalid_request', 'unexpected "redirect_uri"', 400);
        }

        if ($postData['client_id'] !== $codeInfo['client_id']) {
            throw new TokenException('invalid_request', 'unexpected "client_id"', 400);
        }
    }

    private function verifyCodeVerifier($codeChallenge, $codeVerifier)
    {
        if (!hash_equals($codeChallenge, $this->uriEncode(hash('sha256', $codeVerifier, true)))) {
            throw new TokenException('invalid_grant', 'invalid "code_verifier"', 400);
        }
    }

    private function tokenAuthorize(array $getData, array $postData, $userId)
    {
        if ('no' === $postData['approve']) {
            return $this->prepareRedirect(
                '#',
                $getData['redirect_uri'],
                [
                    'error' => 'access_denied',
                    'error_description' => 'user refused authorization',
                    'state' => $getData['state'],
                ]
            );
        }

        $accessToken = $this->getAccessToken(
            $userId,
            $getData['client_id'],
            $getData['scope'],
            null
        );

        return $this->prepareRedirect(
            '#',
            $getData['redirect_uri'],
            [
                'access_token' => $accessToken['access_token'],
                'state' => $getData['state'],
                'expires_in' => $accessToken['expires_in'],
            ]
        );
    }

    private function codeAuthorize(array $getData, array $postData, $userId)
    {
        if ('no' === $postData['approve']) {
            return $this->prepareRedirect(
                '?',
                $getData['redirect_uri'],
                [
                    'error' => 'access_denied',
                    'error_description' => 'user refused authorization',
                    'state' => $getData['state'],
                ]
            );
        }

        $authorizationCode = $this->getAuthorizationCode(
            $userId,
            $getData['client_id'],
            $getData['scope'],
            $getData['redirect_uri'],
            $getData['code_challenge']
        );

        return $this->prepareRedirect(
            '?',
            $getData['redirect_uri'],
            [
                'code' => $authorizationCode,
                'state' => $getData['state'],
            ]
        );
    }

    private function prepareRedirect($querySeparator, $redirectUri, array $queryParameters)
    {
        // if redirectUri already contains '?', the separator becomes '&'
        if ('?' === $querySeparator && false !== strpos($redirectUri, '?')) {
            $querySeparator = '&';
        }

        return sprintf(
            '%s%s%s',
            $redirectUri,
            $querySeparator,
            http_build_query($queryParameters)
        );
    }

    private function getAuthorizationCode($userId, $clientId, $scope, $redirectUri, $codeChallenge)
    {
        $authorizationCodeKey = $this->uriEncode($this->random->get(8));
        $authorizationCode = $this->uriEncode($this->random->get(32));

        $this->tokenStorage->storeCode(
            $userId,
            $authorizationCodeKey,
            $authorizationCode,
            $clientId,
            $scope,
            $redirectUri,
            $this->dateTime,
            $codeChallenge
        );

        return sprintf('%s.%s', $authorizationCodeKey, $authorizationCode);
    }

    /**
     * @return array
     */
    private function getAccessToken($userId, $clientId, $scope, $accessTokenKey)
    {
        // for "token" clients we generate an access_token_key here, for "code"
        // clients we reuse the "authorization_code_key" to be able to track
        // issued access_tokens for a particular "authorization_code" and to
        // prevent authorization code replay
        if (is_null($accessTokenKey)) {
            $accessTokenKey = $this->uriEncode($this->random->get(8));
        }
        $accessToken = $this->uriEncode($this->random->get(32));
        $expiresAt = date_add(clone $this->dateTime, new DateInterval(sprintf('PT%dS', $this->expiresIn)));

        // store it
        $this->tokenStorage->storeToken(
            $userId,
            $accessTokenKey,
            $accessToken,
            $clientId,
            $scope,
            $expiresAt
        );

        // return new token
        return [
            'access_token' => sprintf('%s.%s', $accessTokenKey, $accessToken),
            'expires_in' => $this->expiresIn,
        ];
    }

    private function uriEncode($inputString)
    {
        return strtr(
            rtrim(
                base64_encode($inputString),
                '='
            ),
            '+/',
            '-_'
        );
    }

    // VALIDATORS

    private function validateQueryParameters(array $getData)
    {
        // check all parameters are there
        foreach (['client_id', 'redirect_uri', 'response_type', 'scope', 'state'] as $queryParameter) {
            if (!array_key_exists($queryParameter, $getData)) {
                throw new ValidateException(sprintf('missing "%s" parameter', $queryParameter), 400);
            }
        }

        // check syntax
        // NOTE: no need to validate the redirect_uri, as we do strict matching
        $this->validateClientId($getData['client_id']);
        $this->validateResponseType($getData['response_type']);
        $this->validateScope($getData['scope']);
        $this->validateState($getData['state']);

        if ('code' === $getData['response_type']) {
            foreach (['code_challenge_method', 'code_challenge'] as $queryParameter) {
                if (!array_key_exists($queryParameter, $getData)) {
                    throw new ValidateException(sprintf('missing "%s" parameter', $queryParameter), 400);
                }
            }
            $this->validateCodeChallengeMethod($getData['code_challenge_method']);
            $this->validateCodeChallenge($getData['code_challenge']);
        }
    }

    private function validateTokenPostParameters(array $postData)
    {
        // check all parameters are there
        foreach (['grant_type', 'code', 'redirect_uri', 'client_id'] as $postParameter) {
            if (!array_key_exists($postParameter, $postData)) {
                throw new ValidateException(sprintf('missing "%s" parameter', $postParameter), 400);
            }
        }

        // check syntax
        // NOTE: no need to validate the redirect_uri, as we do strict matching
        $this->validateGrantType($postData['grant_type']);
        $this->validateCode($postData['code']);
        $this->validateClientId($postData['client_id']);

        if ('authorization_code' === $postData['grant_type']) {
            if (!array_key_exists('code_verifier', $postData)) {
                throw new ValidateException('missing "code_verifier" parameter', 400);
            }
            $this->validateCodeVerifier($postData['code_verifier']);
        }
    }

    private function validatePostParameters(array $postData)
    {
        // check all parameters are there
        foreach (['approve'] as $postParameter) {
            if (!array_key_exists($postParameter, $postData)) {
                throw new ValidateException(sprintf('missing "%s" parameter', $postParameter), 400);
            }
        }

        $this->validateApprove($postData['approve']);
    }

    private function validateClient($clientId, $responseType, $redirectUri)
    {
        if(false === $clientInfo = call_user_func($this->getClientInfo, $clientId)) {
            throw new TokenException('invalid_client', sprintf('client not registered', $clientId), 400);
        }

        if ($clientInfo['response_type'] !== $responseType) {
            throw new TokenException('invalid_client', '"response_type" not supported by this client', 400);
        }

        if ($clientInfo['redirect_uri'] !== $redirectUri) {
            throw new TokenException('invalid_client', sprintf('"redirect_uri" not supported by this client', $clientInfo['redirect_uri']), 400);
        }

        return $clientInfo;
    }

    // STRING VALIDATORS

    private function validateClientId($clientId)
    {
        // client-id  = *VSCHAR
        // VSCHAR     = %x20-7E
        if (1 !== preg_match('/^[\x20-\x7E]+$/', $clientId)) {
            throw new ValidateException('invalid "client_id"', 400);
        }
    }

    /**
     * Validate the authorization code.
     */
    private function validateCode($code)
    {
        // code       = 1*VSCHAR
        // VSCHAR     = %x20-7E
        if (1 !== preg_match('/^[\x20-\x7E]+$/', $code)) {
            throw new ValidateException('invalid "code"', 400);
        }
        // the codes we generate MUST also contain a dot "."
        if (false === strpos($code, '.')) {
            throw new ValidateException('invalid "code"', 400);
        }
    }

    private function validateGrantType($grantType)
    {
        if ('authorization_code' !== $grantType) {
            throw new ValidateException('invalid "grant_type"', 400);
        }
    }

    private function validateResponseType($responseType)
    {
        if (!in_array($responseType, ['token', 'code'])) {
            throw new ValidateException('invalid "response_type"', 400);
        }
    }

    private function validateScope($scope)
    {
        // scope       = scope-token *( SP scope-token )
        // scope-token = 1*NQCHAR
        // NQCHAR      = %x21 / %x23-5B / %x5D-7E
        foreach (explode(' ', $scope) as $scopeToken) {
            if (1 !== preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+$/', $scopeToken)) {
                throw new ValidateException('invalid "scope"', 400);
            }
        }
    }

    private function validateState($state)
    {
        // state      = 1*VSCHAR
        // VSCHAR     = %x20-7E
        if (1 !== preg_match('/^[\x20-\x7E]+$/', $state)) {
            throw new ValidateException('invalid "state"', 400);
        }
    }

    private function validateCodeChallengeMethod($codeChallengeMethod)
    {
        if ('S256' !== $codeChallengeMethod) {
            throw new ValidateException('invalid "code_challenge_method"', 400);
        }
    }

    private function validateCodeVerifier($codeVerifier)
    {
        // code-verifier = 43*128unreserved
        // unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
        // ALPHA         = %x41-5A / %x61-7A
        // DIGIT         = %x30-39
        if (1 !== preg_match('/^[\x41-\x5A\x61-\x7A\x30-\x39-._~]{43,128}$/', $codeVerifier)) {
            throw new ValidateException('invalid "code_verifier"', 400);
        }
    }

    private function validateCodeChallenge($codeChallenge)
    {
        // it seems the length of the codeChallenge is always 43 because it is
        // the output of the SHA256 hashing algorithm
        if (1 !== preg_match('/^[\x41-\x5A\x61-\x7A\x30-\x39-_]{43}$/', $codeChallenge)) {
            throw new ValidateException('invalid "code_challenge"', 400);
        }
    }

    private function validateApprove($approve)
    {
        // check they are all syntactically correct
        if (!in_array($approve, ['yes', 'no'])) {
            throw new ValidateException('invalid "approve"', 400);
        }
    }
}
