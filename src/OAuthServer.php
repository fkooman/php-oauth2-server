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
use fkooman\OAuth\Server\Exception\ValidateException;
use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Base64UrlSafe;

class OAuthServer
{
    /** @var callable */
    private $getClientInfo;

    /** @var string */
    private $keyPair;

    /** @var Storage */
    private $storage;

    /** @var RandomInterface */
    private $random;

    /** @var \DateTime */
    private $dateTime;

    /** @var int */
    private $expiresIn = 3600;

    public function __construct(callable $getClientInfo, $keyPair, Storage $storage, RandomInterface $random = null, DateTime $dateTime = null)
    {
        $this->getClientInfo = $getClientInfo;
        $this->keyPair = $keyPair;
        $this->storage = $storage;
        if (is_null($random)) {
            $random = new Random();
        }
        $this->random = $random;
        if (is_null($dateTime)) {
            $dateTime = new DateTime();
        }
        $this->dateTime = $dateTime;
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
        RequestValidator::validateAuthorizeQueryParameters($getData);
        $clientInfo = $this->validateClient($getData['client_id'], $getData['response_type'], $getData['redirect_uri']);
        RequestValidator::validatePkceParameters($clientInfo, $getData);

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
        RequestValidator::validateAuthorizeQueryParameters($getData);
        $clientInfo = $this->validateClient($getData['client_id'], $getData['response_type'], $getData['redirect_uri']);
        RequestValidator::validatePkceParameters($clientInfo, $getData);
        RequestValidator::validateAuthorizePostParameters($postData);

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
     * @return array
     */
    public function postToken(array $postData, $authUser, $authPass)
    {
        RequestValidator::validateTokenPostParameters($postData);
        $clientInfo = $this->validateClient($postData['client_id'], 'code', $postData['redirect_uri']);

        // verify credentials if not a public client
        $this->verifyClientCredentials($postData['client_id'], $clientInfo, $authUser, $authPass);

        // verify the authorization code
        $signedCode = Base64::decode($postData['code']);
        $publicKey = \Sodium\crypto_sign_publickey($this->keyPair);
        if (false === $jsonCode = \Sodium\crypto_sign_open($signedCode, $publicKey)) {
            throw new GrantException('invalid code');
        }

        $codeInfo = json_decode($jsonCode, true);
        // type MUST be "authorization_code"
        if ('authorization_code' !== $codeInfo['type']) {
            throw new GrantException('not an authorization code');
        }
        if ($this->dateTime >= new DateTime($codeInfo['expires_at'])) {
            throw new GrantException('expired code');
        }

        // parameters in POST body need to match the parameters stored with
        // the code
        $this->verifyCodeInfo($postData, $codeInfo);

        // verify code_verifier if public client
        $this->verifyCodeVerifier($clientInfo, $codeInfo, $postData);

        // check if this authorization code was already used for getting an
        // access token in the past
        if (false !== $this->storage->hasAuthorization($codeInfo['auth_key'])) {
            throw new GrantException('code already used');
        }

        $accessToken = $this->getAccessToken(
            $codeInfo['user_id'],
            $postData['client_id'],
            $codeInfo['scope'],
            $codeInfo['auth_key']
        );

        return [
            'access_token' => $accessToken['access_token'],
            'token_type' => 'bearer',
            'expires_in' => $accessToken['expires_in'],
        ];
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
     * @param string|null $authKey
     *
     * @return array
     */
    private function getAccessToken($userId, $clientId, $scope, $authKey)
    {
        // for prevention of replays of authorization codes and the revocation
        // of access tokens when an authorization code is replayed, we use the
        // "auth_key" as a tag for the issued access tokens, this
        // is only relevant for the "authorization code" grant type
        if (is_null($authKey)) {
            $authKey = $this->random->get(16);
        }

        $expiresAt = date_add(clone $this->dateTime, new DateInterval(sprintf('PT%dS', $this->expiresIn)));
        $accessToken = Base64::encode(
            \Sodium\crypto_sign(
                json_encode(
                    [
                        'type' => 'access_token',
                        'auth_key' => $authKey, // to bind it to the authorization code
                        'user_id' => $userId,
                        'client_id' => $clientId,
                        'scope' => $scope,
                        'expires_at' => $expiresAt->format('Y-m-d H:i:s'),
                    ]
                ),
                \Sodium\crypto_sign_secretkey($this->keyPair)
            )
        );

        // store it in the db
        $this->storage->storeAuthorization(
            $authKey,
            $userId,
            $clientId,
            $scope
        );

        return [
            'access_token' => $accessToken,
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
        $expiresAt = date_add(clone $this->dateTime, new DateInterval('PT5M'));

        return Base64::encode(
            \Sodium\crypto_sign(
                json_encode(
                    [
                        'type' => 'authorization_code',
                        'auth_key' => $this->random->get(16),
                        'user_id' => $userId,
                        'client_id' => $clientId,
                        'scope' => $scope,
                        'redirect_uri' => $redirectUri,
                        'code_challenge' => $codeChallenge,
                        'expires_at' => $expiresAt->format('Y-m-d H:i:s'),
                    ]
                ),
                \Sodium\crypto_sign_secretkey($this->keyPair)
            )
        );
    }

    private function verifyCodeInfo(array $postData, array $codeInfo)
    {
        // XXX more fields to verify?!
        if ($postData['client_id'] !== $codeInfo['client_id']) {
            throw new ValidateException('unexpected "client_id"');
        }

        if ($postData['redirect_uri'] !== $codeInfo['redirect_uri']) {
            throw new ValidateException('unexpected "redirect_uri"');
        }
    }

    /**
     * @param array       $clientInfo
     * @param string|null $authPass
     */
    private function verifyClientCredentials($clientId, array $clientInfo, $authUser, $authPass)
    {
        if (array_key_exists('client_secret', $clientInfo)) {
            if ($clientId !== $authUser) {
                throw new ClientException('"client_id" does not match authenticating user', 401);
            }

            if (!is_string($authPass)) {
                throw new ClientException('invalid credentials (no client_secret)', 401);
            }

            if (0 !== \Sodium\compare($clientInfo['client_secret'], $authPass)) {
                throw new ClientException('invalid credentials (invalid client_secret)', 401);
            }
        }
    }

    private function verifyCodeVerifier(array $clientInfo, array $codeInfo, array $postData)
    {
        if (!array_key_exists('client_secret', $clientInfo)) {
            if (!array_key_exists('code_verifier', $postData)) {
                throw new ValidateException('missing "code_verifier" parameter');
            }

            if (0 !== \Sodium\compare($codeInfo['code_challenge'], self::encodeWithoutPadding(hash('sha256', $postData['code_verifier'], true)))) {
                throw new GrantException('unexpected "code_verifier"');
            }
        }
    }

    /**
     * Base64url Encoding without Padding.
     *
     * @see https://tools.ietf.org/html/rfc7636#appendix-A
     */
    private static function encodeWithoutPadding($inputString)
    {
        return rtrim(
            Base64UrlSafe::encode($inputString),
            '='
        );
    }

    /**
     * @param string $clientId
     * @param string $responseType "token" or "code"
     * @param string $redirectUri
     *
     * @return array
     */
    private function validateClient($clientId, $responseType, $redirectUri)
    {
        if (false === $clientInfo = call_user_func($this->getClientInfo, $clientId)) {
            throw new ClientException('client does not exist with this "client_id"', 400);
        }

        if ($clientInfo['response_type'] !== $responseType) {
            throw new ClientException('client does not support this "response_type"', 400);
        }

        if ($clientInfo['redirect_uri'] !== $redirectUri) {
            throw new ClientException('client does not support this "redirect_uri"', 400);
        }

        return $clientInfo;
    }
}
