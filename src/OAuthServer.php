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

use DateInterval;
use DateTime;
use fkooman\OAuth\Server\Exception\ClientException;
use fkooman\OAuth\Server\Exception\GrantException;
use fkooman\OAuth\Server\Exception\ValidateException;
use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Base64UrlSafe;

class OAuthServer
{
    /** @var Storage */
    private $storage;

    /** @var callable */
    private $getClientInfo;

    /** @var string */
    private $keyPair;

    /** @var RandomInterface */
    private $random;

    /** @var \DateTime */
    private $dateTime;

    /** @var int */
    private $expiresIn = 3600;

    /**
     * @param Storage  $storage
     * @param callable $getClientInfo
     * @param string   $keyPair       Base64 encoded output of crypto_sign_keypair()
     */
    public function __construct(Storage $storage, callable $getClientInfo, $keyPair)
    {
        $this->storage = $storage;
        $this->getClientInfo = $getClientInfo;
        $this->keyPair = Base64::decode($keyPair);
        $this->random = new Random();
        $this->dateTime = new DateTime();
    }

    public function setRandom(RandomInterface $random)
    {
        $this->random = $random;
    }

    public function setDateTime(DateTime $dateTime)
    {
        $this->dateTime = $dateTime;
    }

    /**
     * @param int $expiresIn the time (in seconds) an access token will be valid
     */
    public function setExpiresIn($expiresIn)
    {
        $this->expiresIn = $expiresIn;
    }

    /**
     * @return string
     */
    public function getPublicKey()
    {
        return Base64::encode(\Sodium\crypto_sign_publickey($this->keyPair));
    }

    /**
     * Validates the authorization request from the client and returns verified
     * data to show an authorization dialog.
     *
     * @param array $getData
     *
     * @return array
     */
    public function getAuthorize(array $getData)
    {
        $clientInfo = $this->validateAuthorizeRequest($getData);

        return [
            'client_id' => $getData['client_id'],
            'display_name' => $clientInfo['display_name'],
            'scope' => $getData['scope'],
            'redirect_uri' => $getData['redirect_uri'],
        ];
    }

    /**
     * Handles POST request to the "/authorize" endpoint of the OAuth server.
     *
     * This is typically the "form submit" on the "authorize dialog" shown in
     * the browser that the user then accepts or rejects.
     *
     * @param array  $getData
     * @param array  $postData
     * @param string $userId
     *
     * @return string the parameterized redirect URI
     */
    public function postAuthorize(array $getData, array $postData, $userId)
    {
        $this->validateAuthorizeRequest($getData);
        RequestValidator::validateAuthorizePostParameters($postData);

        if ('no' === $postData['approve']) {
            // user did not approve, tell OAuth client
            return $this->prepareRedirectUri(
                'token' === $getData['response_type'], // use fragment
                $getData['redirect_uri'],
                [
                    'error' => 'access_denied',
                    'state' => $getData['state'],
                ]
            );
        }

        // every "authorization" has a unique key that is bound to the
        // authorization code, access tokens(s) and refresh token
        $authKey = $this->random->get(16);
        $this->storage->storeAuthorization(
            $userId,
            $getData['client_id'],
            $getData['scope'],
            $authKey
        );

        if ('code' === $getData['response_type']) {
            // return authorization code
            $authorizationCode = $this->getAuthorizationCode(
                $userId,
                $getData['client_id'],
                $getData['scope'],
                $getData['redirect_uri'],
                $authKey,
                array_key_exists('code_challenge', $getData) ? $getData['code_challenge'] : null
            );

            return $this->prepareRedirectUri(
                false,
                $getData['redirect_uri'],
                [
                    'code' => $authorizationCode,
                    'state' => $getData['state'],
                ]
            );
        } else {
            // "token"
            // return access token
            $accessToken = $this->getAccessToken(
                $userId,
                $getData['client_id'],
                $getData['scope'],
                $authKey
            );

            return $this->prepareRedirectUri(
                true,
                $getData['redirect_uri'],
                [
                    'access_token' => $accessToken,
                    'token_type' => 'bearer',
                    'expires_in' => $this->expiresIn,
                    'state' => $getData['state'],
                ]
            );
        }
    }

    /**
     * Handles POST request to the "/token" endpoint of the OAuth server.
     *
     * @param array       $postData
     * @param string|null $authUser BasicAuth user in case of secret client, null if public client
     * @param string|null $authPass BasicAuth pass in case of secret client, null if public client
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

    /**
     * Validate the request to the "/authorize" endpoint.
     *
     * @param array $getData
     *
     * @return array the client info
     */
    private function validateAuthorizeRequest(array $getData)
    {
        RequestValidator::validateAuthorizeQueryParameters($getData);
        $clientInfo = $this->getClient($getData['client_id']);

        // make sure the provided redirect URI is supported by the client
        if (!self::validateRedirectUri($clientInfo, $getData)) {
            throw new ClientException('client does not support this "redirect_uri"', 400);
        }

        // make sure the response_type is supported by the client
        if ($clientInfo['response_type'] !== $getData['response_type']) {
            throw new ClientException('client does not support this "response_type"', 400);
        }
        if ('token' !== $clientInfo['response_type']) {
            // public code clients require PKCE
            if (!array_key_exists('client_secret', $clientInfo)) {
                RequestValidator::validatePkceParameters($getData);
            }
        }

        return $clientInfo;
    }

    /**
     * @param array       $postData
     * @param string|null $authUser BasicAuth user in case of secret client, null if public client
     * @param string|null $authPass BasicAuth pass in case of secret client, null if public client
     */
    private function postTokenAuthorizationCode(array $postData, $authUser, $authPass)
    {
        $clientInfo = $this->getClient($postData['client_id']);
        $this->verifyClientCredentials($postData['client_id'], $clientInfo, $authUser, $authPass);

        // verify the authorization code
        $signedCode = Base64::decode($postData['code']);
        $publicKey = \Sodium\crypto_sign_publickey($this->keyPair);
        if (false === $jsonCode = \Sodium\crypto_sign_open($signedCode, $publicKey)) {
            throw new GrantException('"code" has invalid signature');
        }

        $codeInfo = json_decode($jsonCode, true);
        if ('authorization_code' !== $codeInfo['type']) {
            throw new GrantException('"code" is not of type authorization_code');
        }

        // check authorization code expiry
        if ($this->dateTime >= new DateTime($codeInfo['expires_at'])) {
            throw new GrantException('"authorization_code" is expired');
        }

        // parameters in POST body need to match the parameters stored with
        // the code
        $this->verifyCodeInfo($postData, $codeInfo);

        // verify code_verifier (iff public client)
        $this->verifyCodeVerifier($clientInfo, $codeInfo, $postData);

        // 1. check if the authorization is still there
        if (false === $this->storage->hasAuthorization($codeInfo['auth_key'])) {
            throw new GrantException('"authorization_code" is no longer authorized');
        }

        // 2. make sure the authKey was not used before
        if (false === $this->storage->logAuthKey($codeInfo['auth_key'])) {
            // authKey was used before, delete authorization according to spec
            // so refresh_tokens and access_tokens can no longer be used
            $this->storage->deleteAuthKey($codeInfo['auth_key']);

            throw new GrantException('"authorization_code" reuse');
        }

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
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'token_type' => 'bearer',
            'expires_in' => $this->expiresIn,
        ];
    }

    /**
     * @param array       $postData
     * @param string|null $authUser BasicAuth user in case of secret client, null if public client
     * @param string|null $authPass BasicAuth pass in case of secret client, null if public client
     */
    private function postTokenRefreshToken(array $postData, $authUser, $authPass)
    {
        // verify the refresh code
        $signedRefreshToken = Base64::decode($postData['refresh_token']);
        $publicKey = \Sodium\crypto_sign_publickey($this->keyPair);
        if (false === $jsonRefreshToken = \Sodium\crypto_sign_open($signedRefreshToken, $publicKey)) {
            throw new GrantException('"refresh_token" has invalid signature');
        }

        $refreshTokenInfo = json_decode($jsonRefreshToken, true);
        if ('refresh_token' !== $refreshTokenInfo['type']) {
            throw new GrantException('"refresh_token" is not of type refresh_token');
        }

        $clientInfo = $this->getClient($refreshTokenInfo['client_id']);
        $this->verifyClientCredentials($refreshTokenInfo['client_id'], $clientInfo, $authUser, $authPass);

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
            'access_token' => $accessToken,
            'token_type' => 'bearer',
            'expires_in' => $this->expiresIn,
        ];
    }

    /**
     * @param bool   $useFragment
     * @param string $redirectUri
     * @param array  $queryParameters
     */
    private function prepareRedirectUri($useFragment, $redirectUri, array $queryParameters)
    {
        if ($useFragment) {
            // for "token" flow we use fragment
            $querySeparator = '#';
        } else {
            // use '&' as separator when redirectUri already contains a '?'
            $querySeparator = false === strpos($redirectUri, '?') ? '?' : '&';
        }

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
     * @return string
     */
    private function getAccessToken($userId, $clientId, $scope, $authKey)
    {
        // for prevention of replays of authorization codes and the revocation
        // of access tokens when an authorization code is replayed, we use the
        // "auth_key" as a tag for the issued access tokens
        $expiresAt = date_add(clone $this->dateTime, new DateInterval(sprintf('PT%dS', $this->expiresIn)));

        return Base64::encode(
            \Sodium\crypto_sign(
                json_encode(
                    [
                        'type' => 'access_token',
                        'auth_key' => $authKey, // to bind it to the authorization
                        'user_id' => $userId,
                        'client_id' => $clientId,
                        'scope' => $scope,
                        'expires_at' => $expiresAt->format('Y-m-d H:i:s'),
                    ]
                ),
                \Sodium\crypto_sign_secretkey($this->keyPair)
            )
        );
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
                        'auth_key' => $authKey, // to bind it to the authorization
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
            if (is_null($authUser)) {
                throw new ClientException('invalid credentials (no authenticating user)', 401);
            }
            if ($clientId !== $authUser) {
                throw new ClientException('"client_id" does not match authenticating user', 401);
            }

            if (!is_string($authPass)) {
                throw new ClientException('invalid credentials (no authenticating pass)', 401);
            }

            if (0 !== \Sodium\compare($clientInfo['client_secret'], $authPass)) {
                throw new ClientException('invalid credentials (invalid authenticating pass)', 401);
            }
        }
    }

    /**
     * @param array $clientInfo
     * @param array $codeInfo
     * @param array $postData
     *
     * @see https://tools.ietf.org/html/rfc7636#appendix-A
     */
    private function verifyCodeVerifier(array $clientInfo, array $codeInfo, array $postData)
    {
        // only for public clients
        if (!array_key_exists('client_secret', $clientInfo)) {
            if (!array_key_exists('code_verifier', $postData)) {
                throw new ValidateException('missing "code_verifier" parameter');
            }

            // constant time compare of the code_challenge compared to the
            // expected value
            $cmp = \Sodium\compare(
                $codeInfo['code_challenge'],
                rtrim(
                    Base64UrlSafe::encode(
                        hash(
                            'sha256',
                            $postData['code_verifier'],
                            true
                        )
                    ),
                    '='
                )
            );

            if (0 !== $cmp) {
                throw new GrantException('invalid "code_verifier"');
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

    private static function validateRedirectUri(array $clientInfo, array $getData)
    {
        $clientRedirectUriList = (array) $clientInfo['redirect_uri'];
        $requestRedirectUri = $getData['redirect_uri'];

        if (in_array($requestRedirectUri, $clientRedirectUriList)) {
            return true;
        }

        // parsing is NOT great... but don't see how to avoid it here, we need
        // to accept all ports and both IPv4 and IPv6 for loopback entries
        foreach ($clientRedirectUriList as $clientRedirectUri) {
            if (0 === strpos($clientRedirectUri, 'http://127.0.0.1:{PORT}/')) {
                // IPv4
                if (self::portMatch($clientRedirectUri, $requestRedirectUri)) {
                    return true;
                }
            }

            if (0 === strpos($clientRedirectUri, 'http://[::1]:{PORT}/')) {
                // IPv6
                if (self::portMatch($clientRedirectUri, $requestRedirectUri)) {
                    return true;
                }
            }
        }

        return false;
    }

    private static function portMatch($clientRedirectUri, $requestRedirectUri)
    {
        if (false === $port = parse_url($requestRedirectUri, PHP_URL_PORT)) {
            return false;
        }
        if (!is_int($port) || 1024 > $port || 65535 < $port) {
            return false;
        }
        $clientRedirectUriWithPort = str_replace('{PORT}', $port, $clientRedirectUri);

        return $requestRedirectUri === $clientRedirectUriWithPort;
    }
}
