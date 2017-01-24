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
use fkooman\OAuth\Server\Exception\GrantException;
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

    /**
     * @param int $expiresIn the time in seconds an access token will be valid
     */
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
        $this->validateAuthorizeQueryParameters($getData);
        $clientInfo = $this->validateClient($getData);
        $this->validatePkce($getData, $clientInfo);

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
        $this->validateAuthorizeQueryParameters($getData);
        $clientInfo = $this->validateClient($getData);
        $this->validatePkce($getData, $clientInfo);
        $this->validateAuthorizePostParameters($postData);

        if ('token' === $getData['response_type']) {
            return $this->tokenAuthorize($getData, $postData, $userId);
        }

        if ('code' === $getData['response_type']) {
            return $this->codeAuthorize($getData, $postData, $userId);
        }

        throw new ValidateException('invalid "response_type"');
    }

    /**
     * @param array       $postData
     * @param string|null $authUser
     * @param string|null $authPass
     *
     * @return TokenResponse
     */
    public function postToken(array $postData, $authUser, $authPass)
    {
        try {
            $this->validateTokenPostParameters($postData);
            $clientInfo = $this->validateClient($postData);

            if (array_key_exists('client_secret', $clientInfo)) {
                if ($postData['client_id'] !== $authUser) {
                    throw new ClientException('"client_id" does not match authenticating user', 401);
                }
                $this->verifyClientCredentials($clientInfo, $authPass);
            }

            list($authorizationCodeKey, $authorizationCode) = explode('.', $postData['code']);
            if (false === $codeInfo = $this->tokenStorage->getCode($authorizationCodeKey)) {
                throw new GrantException('no such code');
            }

            if (!hash_equals($codeInfo['authorization_code'], $authorizationCode)) {
                throw new GrantException('invalid code');
            }

            // check for code expiry, it may be at most 5 minutes old
            $codeTime = new DateTime($codeInfo['issued_at']);
            $codeTime->add(new DateInterval('PT5M'));
            if ($this->dateTime >= $codeTime) {
                throw new GrantException('expired code');
            }

            // parameters in POST body need to match the parameters stored with
            // the code
            $this->verifyCodeInfo($postData, $codeInfo);

            if (!array_key_exists('client_secret', $clientInfo)) {
                // PKCE
                if (!array_key_exists('code_verifier', $postData)) {
                    throw new ValidateException('missing "code_verifier" parameter');
                }
                $this->verifyCodeVerifier($codeInfo['code_challenge'], $postData['code_verifier']);
            }

            // check if this authorization code was already used for getting an
            // access token in the past
            if (false !== $this->tokenStorage->getToken($authorizationCodeKey)) {
                throw new GrantException('code already used');
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
        } catch (ClientException $e) {
            throw new TokenException('invalid_client', $e->getMessage(), $e->getCode());
        } catch (ValidateException $e) {
            throw new TokenException('invalid_request', $e->getMessage(), 400);
        } catch (GrantException $e) {
            throw new TokenException('invalid_grant', $e->getMessage(), 400);
        }
    }

    private function tokenAuthorize(array $getData, array $postData, $userId)
    {
        if ('no' === $postData['approve']) {
            return $this->getUserRefused('#', $getData['redirect_uri'], $getData['state']);
        }

        $accessToken = $this->getAccessToken(
            $userId,
            $getData['client_id'],
            $getData['scope'],
            null
        );

        return $this->prepareRedirectUri(
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
            return $this->getUserRefused('?', $getData['redirect_uri'], $getData['state']);
        }

        $authorizationCode = $this->getAuthorizationCode(
            $userId,
            $getData['client_id'],
            $getData['scope'],
            $getData['redirect_uri'],
            array_key_exists('code_challenge', $getData) ? $getData['code_challenge'] : null
        );

        return $this->prepareRedirectUri(
            '?',
            $getData['redirect_uri'],
            [
                'code' => $authorizationCode,
                'state' => $getData['state'],
            ]
        );
    }

    private function getUserRefused($querySeparator, $redirectUri, $state)
    {
        return $this->prepareRedirectUri(
            $querySeparator,
            $redirectUri,
            [
                'error' => 'access_denied',
                'error_description' => 'user refused authorization',
                'state' => $state,
            ]
        );
    }

    private function prepareRedirectUri($querySeparator, $redirectUri, array $queryParameters)
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

    /**
     * @param string      $userId
     * @param string      $clientId
     * @param string      $scope
     * @param string|null $accessTokenKey
     *
     * @return array
     */
    private function getAccessToken($userId, $clientId, $scope, $accessTokenKey)
    {
        // for prevention of replays of authorization codes and the revocation
        // of access tokens when an authorization code is replayed, we use the
        // "authorization_code_key" as a tag for the issued access tokens, this
        // is only relevant for the "authorization code" grant type
        if (is_null($accessTokenKey)) {
            $accessTokenKey = $this->uriEncode($this->random->get(16));
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

        return [
            'access_token' => sprintf('%s.%s', $accessTokenKey, $accessToken),
            'expires_in' => $this->expiresIn,
        ];
    }

    /**
     * @param string      $userId
     * @param string      $clientId
     * @param string      $scope
     * @param string      $redirectUri
     * @param string|null $codeChallenge required for "public" clients
     *
     * @return string
     */
    private function getAuthorizationCode($userId, $clientId, $scope, $redirectUri, $codeChallenge)
    {
        $authorizationCodeKey = $this->uriEncode($this->random->get(16));
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

    private function verifyCodeInfo(array $postData, array $codeInfo)
    {
        if ($postData['client_id'] !== $codeInfo['client_id']) {
            throw new ValidateException('unexpected "client_id"');
        }

        if ($postData['redirect_uri'] !== $codeInfo['redirect_uri']) {
            throw new ValidateException('unexpected "redirect_uri"');
        }
    }

    private function verifyClientCredentials(array $clientInfo, $authPass)
    {
        if (!is_string($authPass)) {
            throw new ClientException('invalid credentials (no password)', 401);
        }

        if (!hash_equals($clientInfo['client_secret'], $authPass)) {
            throw new ClientException('invalid credentials (wrong password)', 401);
        }
    }

    private function verifyCodeVerifier($codeChallenge, $codeVerifier)
    {
        if (!hash_equals($codeChallenge, $this->uriEncode(hash('sha256', $codeVerifier, true)))) {
            throw new GrantException('unexpected "code_verifier"');
        }
    }

    private function validatePkce(array $getData, array $clientInfo)
    {
        if ('code' !== $clientInfo['response_type']) {
            return;
        }

        if (array_key_exists('client_secret', $clientInfo)) {
            return;
        }

        // public client, PKCE required
        if (!array_key_exists('code_challenge_method', $getData)) {
            throw new ValidateException('missing "code_challenge_method" parameter');
        }
        if (!array_key_exists('code_challenge', $getData)) {
            throw new ValidateException('missing "code_challenge" parameter');
        }
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

    private function validateAuthorizeQueryParameters(array $getData)
    {
        // REQUIRED
        foreach (['client_id', 'redirect_uri', 'response_type', 'scope', 'state'] as $queryParameter) {
            if (!array_key_exists($queryParameter, $getData)) {
                throw new ValidateException(sprintf('missing "%s" parameter', $queryParameter));
            }
        }

        // NOTE: no need to validate the redirect_uri, as we do strict matching
        $this->validateClientId($getData['client_id']);
        $this->validateResponseType($getData['response_type']);
        $this->validateScope($getData['scope']);
        $this->validateState($getData['state']);

        // OPTIONAL
        if (array_key_exists('code_challenge_method', $getData)) {
            $this->validateCodeChallengeMethod($getData['code_challenge_method']);
        }
        if (array_key_exists('code_challenge', $getData)) {
            $this->validateCodeChallenge($getData['code_challenge']);
        }
    }

    private function validateAuthorizePostParameters(array $postData)
    {
        if (!array_key_exists('approve', $postData)) {
            throw new ValidateException('missing "approve" parameter');
        }

        $this->validateApprove($postData['approve']);
    }

    private function validateTokenPostParameters(array $postData)
    {
        // REQUIRED
        foreach (['grant_type', 'code', 'redirect_uri', 'client_id'] as $postParameter) {
            if (!array_key_exists($postParameter, $postData)) {
                throw new ValidateException(sprintf('missing "%s" parameter', $postParameter));
            }
        }

        // check syntax
        // NOTE: no need to validate the redirect_uri, as we do strict matching
        $this->validateGrantType($postData['grant_type']);
        $this->validateCode($postData['code']);
        $this->validateClientId($postData['client_id']);

        // OPTIONAL
        if (array_key_exists('code_verifier', $postData)) {
            $this->validateCodeVerifier($postData['code_verifier']);
        }
    }

    /**
     * @return array
     */
    private function validateClient(array $getData)
    {
        if (false === $clientInfo = call_user_func($this->getClientInfo, $getData['client_id'])) {
            throw new ClientException('no such client', 400);
        }

        if ('code' === $clientInfo['response_type']) {
            if (array_key_exists('response_type', $getData) && 'code' === $getData['response_type']) {
                return $clientInfo;
            }
            if (array_key_exists('grant_type', $getData) && 'authorization_code' === $getData['grant_type']) {
                return $clientInfo;
            }

            throw new ClientException('client does not support this "response_type" or "grant_Type"', 400);
        }

        if ($clientInfo['redirect_uri'] !== $getData['redirect_uri']) {
            throw new ClientException('client does not support this "redirect_uri"', 400);
        }

        return $clientInfo;
    }

    // STRING VALIDATORS

    private function validateClientId($clientId)
    {
        // client-id  = *VSCHAR
        // VSCHAR     = %x20-7E
        if (1 !== preg_match('/^[\x20-\x7E]+$/', $clientId)) {
            throw new ValidateException('invalid "client_id"');
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
            throw new ValidateException('invalid "code"');
        }
        // the codes we generate MUST also contain a dot "."
        if (false === strpos($code, '.')) {
            throw new ValidateException('invalid "code"');
        }
    }

    private function validateGrantType($grantType)
    {
        if ('authorization_code' !== $grantType) {
            throw new ValidateException('invalid "grant_type"');
        }
    }

    private function validateResponseType($responseType)
    {
        if (!in_array($responseType, ['token', 'code'])) {
            throw new ValidateException('invalid "response_type"');
        }
    }

    private function validateScope($scope)
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

    private function validateState($state)
    {
        // state      = 1*VSCHAR
        // VSCHAR     = %x20-7E
        if (1 !== preg_match('/^[\x20-\x7E]+$/', $state)) {
            throw new ValidateException('invalid "state"');
        }
    }

    private function validateCodeChallengeMethod($codeChallengeMethod)
    {
        if ('S256' !== $codeChallengeMethod) {
            throw new ValidateException('invalid "code_challenge_method"');
        }
    }

    private function validateCodeVerifier($codeVerifier)
    {
        // code-verifier = 43*128unreserved
        // unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
        // ALPHA         = %x41-5A / %x61-7A
        // DIGIT         = %x30-39
        if (1 !== preg_match('/^[\x41-\x5A\x61-\x7A\x30-\x39-._~]{43,128}$/', $codeVerifier)) {
            throw new ValidateException('invalid "code_verifier"');
        }
    }

    private function validateCodeChallenge($codeChallenge)
    {
        // it seems the length of the codeChallenge is always 43 because it is
        // the output of the SHA256 hashing algorithm
        if (1 !== preg_match('/^[\x41-\x5A\x61-\x7A\x30-\x39-_]{43}$/', $codeChallenge)) {
            throw new ValidateException('invalid "code_challenge"');
        }
    }

    private function validateApprove($approve)
    {
        if (!in_array($approve, ['yes', 'no'])) {
            throw new ValidateException('invalid "approve"');
        }
    }
}
