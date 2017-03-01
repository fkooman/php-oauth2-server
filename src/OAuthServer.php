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
        $this->keyPair = Base64::decode($keyPair);
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
        $clientInfo = $this->getClient($getData['client_id']);
        $this->validateRedirectUri($clientInfo, $getData['redirect_uri']);
        RequestValidator::validatePkceParameters($clientInfo, $getData);

        return [
            'client_id' => $getData['client_id'],
            'display_name' => $clientInfo['display_name'],
            'scope' => $getData['scope'],
            'redirect_uri' => $getData['redirect_uri'],
        ];
    }

    /**
     * @param array  $getData
     * @param array  $postData
     * @param string $userId
     *
     * @return string the redirect_uri
     */
    public function postAuthorize(array $getData, array $postData, $userId)
    {
        RequestValidator::validateAuthorizeQueryParameters($getData);
        $clientInfo = $this->getClient($getData['client_id']);
        $this->validateRedirectUri($clientInfo, $getData['redirect_uri']);
        RequestValidator::validatePkceParameters($clientInfo, $getData);
        RequestValidator::validateAuthorizePostParameters($postData);

        return $this->codeAuthorize($getData, $postData, $userId);
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
        switch ($postData['grant_type']) {
            case 'authorization_code':
                return $this->postTokenAuthorizationCode($postData, $authUser, $authPass);
            case 'refresh_token':
                return $this->postTokenRefreshToken($postData, $authUser, $authPass);
            default:
                throw new ValidateException('invalid "grant_type"');
        }
    }

    private function postTokenAuthorizationCode(array $postData, $authUser, $authPass)
    {
        $clientInfo = $this->getClient($postData['client_id']);
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
            // it was used, delete the authorization
            $this->storage->deleteAuthorization($codeInfo['auth_key']);

            throw new GrantException('code already used');
        }

        // as soon as we get an access token we store the authorization and
        // make it impossible for this authorization code to be reused again
        $this->storage->storeAuthorization(
            $codeInfo['user_id'],
            $postData['client_id'],
            $codeInfo['scope'],
            $codeInfo['auth_key']
        );

        $accessToken = $this->getAccessToken(
            $codeInfo['user_id'],
            $postData['client_id'],
            $codeInfo['scope'],
            $codeInfo['auth_key']
        );

        $refreshToken = $this->getRefreshToken(
            $codeInfo['user_id'],
            $postData['client_id'],
            $codeInfo['scope'],
            $codeInfo['auth_key']
        );

        return [
            'access_token' => $accessToken['access_token'],
            'refresh_token' => $refreshToken,
            'token_type' => 'bearer',
            'expires_in' => $accessToken['expires_in'],
        ];
    }

    private function postTokenRefreshToken(array $postData, $authUser, $authPass)
    {
        // verify the refresh code
        $signedRefreshToken = Base64::decode($postData['refresh_token']);
        $publicKey = \Sodium\crypto_sign_publickey($this->keyPair);
        if (false === $jsonRefreshToken = \Sodium\crypto_sign_open($signedRefreshToken, $publicKey)) {
            throw new GrantException('invalid refresh_token');
        }

        $refreshTokenInfo = json_decode($jsonRefreshToken, true);
        // type MUST be "refresh_token"
        if ('refresh_token' !== $refreshTokenInfo['type']) {
            throw new GrantException('not a refresh token');
        }

        $clientInfo = $this->getClient($refreshTokenInfo['client_id']);
        $this->verifyClientCredentials($refreshTokenInfo['client_id'], $clientInfo, $authUser, $authPass);

        // XXX make sure the authorization still exists before accepting the
        // refresh token!

        // parameters in POST body need to match the parameters stored with
        // the refresh token
        $this->verifyRefreshTokenInfo($postData, $refreshTokenInfo);

        $accessToken = $this->getAccessToken(
            $refreshTokenInfo['user_id'],
            $refreshTokenInfo['client_id'],
            $postData['scope'],
            $refreshTokenInfo['auth_key']
        );

        return [
            'access_token' => $accessToken['access_token'],
            'token_type' => 'bearer',
            'expires_in' => $accessToken['expires_in'],
        ];
    }

    /**
     * @param array  $getData
     * @param array  $postData
     * @param string $userId
     */
    private function codeAuthorize(array $getData, array $postData, $userId)
    {
        if ('no' === $postData['approve']) {
            return $this->prepareRedirectUri(
                $getData['redirect_uri'],
                [
                    'error' => 'access_denied',
                    'error_description' => 'user refused authorization',
                    'state' => $getData['state'],
                ]
            );
        }

        $authKey = $this->random->get(16);
        $authorizationCode = $this->getAuthorizationCode(
            $userId,
            $getData['client_id'],
            $getData['scope'],
            $getData['redirect_uri'],
            $authKey,
            array_key_exists('code_challenge', $getData) ? $getData['code_challenge'] : null
        );

        return $this->prepareRedirectUri(
            $getData['redirect_uri'],
            [
                'code' => $authorizationCode,
                'state' => $getData['state'],
            ]
        );
    }

    /**
     * @param string $redirectUri
     * @param array  $queryParameters
     */
    private function prepareRedirectUri($redirectUri, array $queryParameters)
    {
        // if redirectUri already contains '?', the separator becomes '&'
        $querySeparator = false === strpos($redirectUri, '?') ? '?' : '&';

        return sprintf(
            '%s%s%s',
            $redirectUri,
            $querySeparator,
            http_build_query($queryParameters)
        );
    }

    /**
     * @param string $userId
     * @param string $clientId
     * @param string $scope
     * @param string $authKey
     *
     * @return array
     */
    private function getAccessToken($userId, $clientId, $scope, $authKey)
    {
        // for prevention of replays of authorization codes and the revocation
        // of access tokens when an authorization code is replayed, we use the
        // "auth_key" as a tag for the issued access tokens
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

        return [
            'access_token' => $accessToken,
            'expires_in' => $this->expiresIn,
        ];
    }

    /**
     * @param string $userId
     * @param string $clientId
     * @param string $scope
     * @param string $authKey
     *
     * @return string
     */
    private function getRefreshToken($userId, $clientId, $scope, $authKey)
    {
        return Base64::encode(
            \Sodium\crypto_sign(
                json_encode(
                    [
                        'type' => 'refresh_token',
                        'auth_key' => $authKey, // to bind it to the authorization code
                        'user_id' => $userId,
                        'client_id' => $clientId,
                        'scope' => $scope,
                    ]
                ),
                \Sodium\crypto_sign_secretkey($this->keyPair)
            )
        );
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
    private function getAuthorizationCode($userId, $clientId, $scope, $redirectUri, $authKey, $codeChallenge)
    {
        // authorization codes expire after 5 minutes
        $expiresAt = date_add(clone $this->dateTime, new DateInterval('PT5M'));

        return Base64::encode(
            \Sodium\crypto_sign(
                json_encode(
                    [
                        'type' => 'authorization_code',
                        'auth_key' => $authKey,
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

    /**
     * @param array $postData
     * @param array $codeInfo
     */
    private function verifyCodeInfo(array $postData, array $codeInfo)
    {
        // XXX more fields to verify?!
        // XXX ValidateException is correct here?
        if ($postData['client_id'] !== $codeInfo['client_id']) {
            throw new ValidateException('unexpected "client_id"');
        }

        if ($postData['redirect_uri'] !== $codeInfo['redirect_uri']) {
            throw new ValidateException('unexpected "redirect_uri"');
        }
    }

    /**
     * @param array $postData
     * @param array $refreshTokenInfo
     */
    private function verifyRefreshTokenInfo(array $postData, array $refreshTokenInfo)
    {
        // XXX more fields to verify?!
        if ($postData['scope'] !== $refreshTokenInfo['scope']) {
            throw new ValidateException('unexpected "scope"');
        }

        // make sure the authorization still exists
        if (!$this->storage->hasAuthorization($refreshTokenInfo['auth_key'])) {
            throw new GrantException('refresh_token is no longer authorized');
        }
    }

    /**
     * @param string      $clientId
     * @param array       $clientInfo
     * @param string|null $authUser
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

    /**
     * @param array $clientInfo
     * @param array $codeInfo
     * @param array $postData
     */
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
     * @param string $clientId
     *
     * @return array
     */
    private function getClient($clientId)
    {
        if (false === $clientInfo = call_user_func($this->getClientInfo, $clientId)) {
            throw new ClientException('client does not exist with this "client_id"', 400);
        }

        return $clientInfo;
    }

    /**
     * @param array  $clientInfo
     * @param string $redirectUri
     */
    private function validateRedirectUri(array $clientInfo, $redirectUri)
    {
        if ($clientInfo['redirect_uri'] !== $redirectUri) {
            throw new ClientException('client does not support this "redirect_uri"', 400);
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
}
