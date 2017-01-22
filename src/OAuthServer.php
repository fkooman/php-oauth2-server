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
use fkooman\OAuth\Server\Exception\ClientException;
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
    public function getAuthorize(array $getData, $userId)
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
        // for now only "public" clients without authentication
        try {
            $this->validateTokenPostParameters($postData);
            $this->validateClient($postData['client_id'], 'code', $postData['redirect_uri']);
        } catch (ValidateException $e) {
            throw new TokenException('invalid_request', $e->getMessage(), 400);
        } catch (ClientException $e) {
            throw new TokenException('invalid_client', $e->getMessage(), 400);
        }

    // XXX
// https://tools.ietf.org/html/rfc6749#section-5.2

// the authorization server MUST
//               respond with an HTTP 401 (Unauthorized) status code and
//               include the "WWW-Authenticate" response header field
//               matching the authentication scheme used by the client.

        // XXX does NOT necesarilly contain a ".", we have to make sure!
        list($authorizationCodeKey, $authorizationCode) = explode('.', $postData['code']);

        // XXX the code MUST also be deleted, or marked *used*, it MUST not be reused
//https://tools.ietf.org/html/rfc6749#section-4.1.2

//    If an authorization code is used more than
//    once, the authorization server MUST deny the request and SHOULD
//    revoke (when possible) all tokens previously issued based on
//    that authorization code.  The authorization code is bound to
//    the client identifier and redirection URI.
        $codeInfo = $this->tokenStorage->getCode($authorizationCodeKey);

        if (!hash_equals($codeInfo['authorization_code'], $authorizationCode)) {
            throw new TokenException('invalid_grant', 'invalid "authorization_code"', 400);
        }
        // XXX verify the response codes!

        // validate the code_verifier
        $codeChallenge = $codeInfo['code_challenge'];
        $codeVerifier = $postData['code_verifier'];
        if (!hash_equals($codeChallenge, $this->uriEncode(hash('sha256', $codeVerifier, true)))) {
            throw new TokenException('invalid_grant', 'invalid "code_verifier"', 400);
        }

        // check for code expiry, it may be at most 5 minutes old (more strict
        // than specification that recommends 10 minutes)
        $codeTime = new DateTime($codeInfo['issued_at']);
        $codeTime->add(new DateInterval('PT5M'));
        if ($this->dateTime >= $codeTime) {
            throw new TokenException('invalid_grant', 'expired "authorization_code"', 400);
        }

        if ($postData['redirect_uri'] !== $codeInfo['redirect_uri']) {
            throw new TokenException('invalid_request', 'unexpected "redirect_uri"', 400);
        }

        if ($postData['client_id'] !== $codeInfo['client_id']) {
            throw new TokenException('invalid_request', 'unexpected "client_id"', 400);
        }

        // XXX we should link the code to the access token to be able to revoke it?
        $accessToken = $this->getAccessToken(
            $codeInfo['user_id'],
            $postData['client_id'],
            $codeInfo['scope']
        );

        return new TokenResponse(
            [
                'access_token' => $accessToken['access_token'],
                'token_type' => 'bearer',
                'expires_in' => $accessToken['expires_in'],
            ]
        );
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
            $getData['scope']
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
            $getData['code_challenge']     // XXX if non public client can be NULL
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
    private function getAccessToken($userId, $clientId, $scope)
    {
        // check if we already have a token that is still valid
        if (false === $accessToken = $this->hasToken($userId, $clientId, $scope)) {
            // get a new one
            $accessToken = $this->newToken($userId, $clientId, $scope);
        }

        return [
            'access_token' => sprintf('%s.%s', $accessToken['access_token_key'], $accessToken['access_token']),
            'expires_in' => $accessToken['expires_in'],
        ];
    }

    private function hasToken($userId, $clientId, $scope)
    {
        $existingToken = $this->tokenStorage->getExistingToken($userId, $clientId, $scope);
        if (false === $existingToken) {
            return false;
        }

        // check if it is still valid
        // XXX think about generating a new one when the token _almost_ expires
        $expiresAt = new DateTime($existingToken['expires_at']);
        if ($expiresAt <= $this->dateTime) {
            return false;
        }

        // return existing token
        return [
            'access_token_key' => $existingToken['access_token_key'],
            'access_token' => $existingToken['access_token'],
            'expires_in' => $expiresAt->getTimestamp() - $this->dateTime->getTimestamp(),
        ];
    }

    private function newToken($userId, $clientId, $scope)
    {
        $accessTokenKey = $this->uriEncode($this->random->get(8));
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
            'access_token_key' => $accessTokenKey,
            'access_token' => $accessToken,
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

        // XXX if client is not public this is not needed!
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
        $clientInfo = call_user_func($this->getClientInfo, $clientId);
        if (false === $clientInfo) {
            throw new ClientException(sprintf('client not registered', $clientId), 400);
        }

        if ($clientInfo['response_type'] !== $responseType) {
            throw new ClientException('"response_type" not supported by this client', 400);
        }

        if ($clientInfo['redirect_uri'] !== $redirectUri) {
            throw new ClientException(sprintf('"redirect_uri" not supported by this client', $clientInfo['redirect_uri']), 400);
        }

        return $clientInfo;
    }

    // STRING VALIDATORS

    private function validateClientId($clientId)
    {
        if (1 !== preg_match('/^[\x20-\x7E]+$/', $clientId)) {
            throw new ValidateException('invalid "client_id"', 400);
        }
    }

    /**
     * Validate the authorization code.
     */
    private function validateCode($code)
    {
        if (1 !== preg_match('/^[\x20-\x7E]+$/', $code)) {
            throw new ValidateException('invalid "code"', 400);
        }
        // the codes we generate also contain a dot "."
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
        // XXX do actual "scope" syntax validation here
        if ('config' !== $scope) {
            throw new ValidateException('invalid "scope"', 400);
        }
    }

    private function validateState($state)
    {
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
        // unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
        // ALPHA = %x41-5A / %x61-7A
        // DIGIT = %x30-39
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
