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

use DateInterval;
use DateTime;
use DateTimeImmutable;
use fkooman\OAuth\Server\Exception\InvalidClientException;
use fkooman\OAuth\Server\Exception\InvalidGrantException;
use fkooman\OAuth\Server\Exception\InvalidRequestException;
use fkooman\OAuth\Server\Exception\ServerErrorException;
use fkooman\OAuth\Server\Http\HtmlResponse;
use fkooman\OAuth\Server\Http\JsonResponse;
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

    /** @var \DateTimeImmutable */
    private $dateTime;

    /** @var \DateInterval */
    private $accessTokenExpiry;

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
        $this->dateTime = new DateTimeImmutable();
        $this->accessTokenExpiry = new DateInterval('PT1H');    // 1 hour
    }

    /**
     * @return void
     */
    public function setRandom(RandomInterface $random)
    {
        $this->random = $random;
    }

    /**
     * @return void
     */
    public function setDateTime(DateTime $dateTime)
    {
        $this->dateTime = DateTimeImmutable::createFromMutable($dateTime);
    }

    /**
     * @param int $expiresIn the time (in seconds) an access token will be valid
     *
     * @deprecated use setExpiry
     *
     * @return void
     */
    public function setExpiresIn($expiresIn)
    {
        $this->accessTokenExpiry = new DateInterval(sprintf('PT%dS', $expiresIn));
    }

    /**
     * @param DateInterval $accessTokenExpiry
     *
     * @return void
     */
    public function setExpiry(DateInterval $accessTokenExpiry)
    {
        $this->accessTokenExpiry = $accessTokenExpiry;
    }

    /**
     * @return string
     */
    public function getPublicKey()
    {
        return Base64::encode(sodium_crypto_sign_publickey($this->keyPair));
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
            'display_name' => $clientInfo->getDisplayName(),
            'scope' => $getData['scope'],
            'redirect_uri' => $getData['redirect_uri'],
        ];
    }

    /**
     * Validates the authorization request from the client and returns
     * authorize response in case the client does NOT require approval by the
     * user (resource owner).
     *
     * @param array  $getData
     * @param string $userId
     *
     * @return Http\Response|false
     */
    public function getAuthorizeResponse(array $getData, $userId)
    {
        $clientInfo = $this->validateAuthorizeRequest($getData);
        if ($clientInfo->getRequireApproval()) {
            return false;
        }

        return $this->postAuthorize($getData, ['approve' => 'yes'], $userId);
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
     * @return HtmlResponse
     */
    public function postAuthorize(array $getData, array $postData, $userId)
    {
        $this->validateAuthorizeRequest($getData);
        RequestValidator::validateAuthorizePostParameters($postData);

        if ('no' === $postData['approve']) {
            // user did not approve, tell OAuth client
            return new HtmlResponse(
                '',
                [
                    'Location' => self::prepareRedirectUri(
                        $getData['redirect_uri'],
                        [
                            'error' => 'access_denied',
                            'state' => $getData['state'],
                        ]
                    ),
                ],
                302
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

        // return authorization code
        $authorizationCode = $this->getAuthorizationCode(
            $userId,
            $getData['client_id'],
            $getData['scope'],
            $getData['redirect_uri'],
            $authKey,
            array_key_exists('code_challenge', $getData) ? $getData['code_challenge'] : null
        );

        return new HtmlResponse(
            '',
            [
                'Location' => self::prepareRedirectUri(
                    $getData['redirect_uri'],
                    [
                        'code' => $authorizationCode,
                        'state' => $getData['state'],
                    ]
                ),
            ],
            302
        );
    }

    /**
     * Handles POST request to the "/token" endpoint of the OAuth server.
     *
     * @param array       $postData
     * @param string|null $authUser BasicAuth user in case of secret client, null if public client
     * @param string|null $authPass BasicAuth pass in case of secret client, null if public client
     *
     * @return JsonResponse
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
                throw new InvalidRequestException('invalid "grant_type"');
        }
    }

    /**
     * Validate the request to the "/authorize" endpoint.
     *
     * @param array $getData
     *
     * @return ClientInfo
     */
    private function validateAuthorizeRequest(array $getData)
    {
        RequestValidator::validateAuthorizeQueryParameters($getData);
        $clientInfo = $this->getClient($getData['client_id']);

        // make sure the provided redirect URI is supported by the client
        if (!$clientInfo->isValidRedirectUri($getData['redirect_uri'])) {
            throw new InvalidClientException('client does not support this "redirect_uri"');
        }

        if (null === $clientInfo->getSecret()) {
            RequestValidator::validatePkceParameters($getData);
        }

        return $clientInfo;
    }

    /**
     * @param array       $postData
     * @param string|null $authUser BasicAuth user in case of secret client, null if public client
     * @param string|null $authPass BasicAuth pass in case of secret client, null if public client
     *
     * @return JsonResponse
     */
    private function postTokenAuthorizationCode(array $postData, $authUser, $authPass)
    {
        $clientInfo = $this->getClient($postData['client_id']);
        $this->verifyClientCredentials($postData['client_id'], $clientInfo, $authUser, $authPass);

        // verify the authorization code
        $codeInfo = $this->verify($postData['code']);
        if ('authorization_code' !== $codeInfo['type']) {
            throw new InvalidGrantException('"code" is not of type authorization_code');
        }

        // check authorization code expiry
        if ($this->dateTime >= new DateTimeImmutable($codeInfo['expires_at'])) {
            throw new InvalidGrantException('"authorization_code" is expired');
        }

        // parameters in POST body need to match the parameters stored with
        // the code
        $this->verifyCodeInfo($postData, $codeInfo);

        // verify code_verifier (iff public client)
        $this->verifyCodeVerifier($clientInfo, $codeInfo, $postData);

        // 1. check if the authorization is still there
        if (false === $this->storage->hasAuthorization($codeInfo['auth_key'])) {
            throw new InvalidGrantException('"authorization_code" is no longer authorized');
        }

        // 2. make sure the authKey was not used before
        if (false === $this->storage->logAuthKey($codeInfo['auth_key'])) {
            // authKey was used before, delete authorization according to spec
            // so refresh_tokens and access_tokens can no longer be used
            $this->storage->deleteAuthKey($codeInfo['auth_key']);

            throw new InvalidGrantException('"authorization_code" reuse');
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

        return new JsonResponse(
            [
                'access_token' => $accessToken,
                'refresh_token' => $refreshToken,
                'token_type' => 'bearer',
                'expires_in' => $this->toExpiresIn($this->accessTokenExpiry),
            ],
            // The authorization server MUST include the HTTP "Cache-Control"
            // response header field [RFC2616] with a value of "no-store" in any
            // response containing tokens, credentials, or other sensitive
            // information, as well as the "Pragma" response header field [RFC2616]
            // with a value of "no-cache".
            [
                'Cache-Control' => 'no-store',
                'Pragma' => 'no-cache',
            ]
        );
    }

    /**
     * @param array       $postData
     * @param string|null $authUser BasicAuth user in case of secret client, null if public client
     * @param string|null $authPass BasicAuth pass in case of secret client, null if public client
     *
     * @return JsonResponse
     */
    private function postTokenRefreshToken(array $postData, $authUser, $authPass)
    {
        // verify the refresh code
        $refreshTokenInfo = $this->verify($postData['refresh_token']);
        if ('refresh_token' !== $refreshTokenInfo['type']) {
            throw new InvalidGrantException('"refresh_token" is not of type refresh_token');
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

        return new JsonResponse(
            [
                'access_token' => $accessToken,
                'token_type' => 'bearer',
                'expires_in' => $this->toExpiresIn($this->accessTokenExpiry),
            ],
            // The authorization server MUST include the HTTP "Cache-Control"
            // response header field [RFC2616] with a value of "no-store" in any
            // response containing tokens, credentials, or other sensitive
            // information, as well as the "Pragma" response header field [RFC2616]
            // with a value of "no-cache".
            [
                'Cache-Control' => 'no-store',
                'Pragma' => 'no-cache',
            ]
        );
    }

    /**
     * @param string $redirectUri
     * @param array  $queryParameters
     *
     * @return string
     */
    private static function prepareRedirectUri($redirectUri, array $queryParameters)
    {
        return sprintf(
            '%s%s%s',
            $redirectUri,
            false === strpos($redirectUri, '?') ? '?' : '&',
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
        $expiresAt = $this->dateTime->add($this->accessTokenExpiry);

        return $this->sign(
            [
                'type' => 'access_token',
                'auth_key' => $authKey, // to bind it to the authorization
                'user_id' => $userId,
                'client_id' => $clientId,
                'scope' => $scope,
                'expires_at' => $expiresAt->format('Y-m-d H:i:s'),
            ]
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
        return $this->sign(
            [
                'type' => 'refresh_token',
                'auth_key' => $authKey, // to bind it to the authorization
                'user_id' => $userId,
                'client_id' => $clientId,
                'scope' => $scope,
            ]
        );
    }

    /**
     * @param string      $userId
     * @param string      $clientId
     * @param string      $scope
     * @param string      $redirectUri
     * @param string      $authKey
     * @param string|null $codeChallenge required for "public" clients
     *
     * @return string
     */
    private function getAuthorizationCode($userId, $clientId, $scope, $redirectUri, $authKey, $codeChallenge)
    {
        // authorization codes expire after 5 minutes
        $expiresAt = $this->dateTime->add(new DateInterval('PT5M'));

        return $this->sign(
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
        );
    }

    /**
     * @param array $postData
     * @param array $codeInfo
     *
     * @return void
     */
    private function verifyCodeInfo(array $postData, array $codeInfo)
    {
        if ($postData['client_id'] !== $codeInfo['client_id']) {
            throw new InvalidRequestException('unexpected "client_id"');
        }

        if ($postData['redirect_uri'] !== $codeInfo['redirect_uri']) {
            throw new InvalidRequestException('unexpected "redirect_uri"');
        }
    }

    /**
     * @param array $postData
     * @param array $refreshTokenInfo
     *
     * @return void
     */
    private function verifyRefreshTokenInfo(array $postData, array $refreshTokenInfo)
    {
        if ($postData['scope'] !== $refreshTokenInfo['scope']) {
            throw new InvalidRequestException('unexpected "scope"');
        }

        // make sure the authorization still exists
        if (!$this->storage->hasAuthorization($refreshTokenInfo['auth_key'])) {
            throw new InvalidGrantException('refresh_token is no longer authorized');
        }
    }

    /**
     * @param string      $clientId
     * @param ClientInfo  $clientInfo
     * @param string|null $authUser
     * @param string|null $authPass
     *
     * @return void
     */
    private function verifyClientCredentials($clientId, ClientInfo $clientInfo, $authUser, $authPass)
    {
        $clientSecret = $clientInfo->getSecret();
        if (null !== $clientSecret) {
            if (null === $authUser) {
                throw new InvalidClientException('invalid credentials (no authenticating user)');
            }
            if ($clientId !== $authUser) {
                throw new InvalidClientException('"client_id" does not match authenticating user');
            }

            if (!is_string($authPass)) {
                throw new InvalidClientException('invalid credentials (no authenticating pass)');
            }

            if (false === hash_equals($clientSecret, $authPass)) {
                throw new InvalidClientException('invalid credentials (invalid authenticating pass)');
            }
        }
    }

    /**
     * @param ClientInfo $clientInfo
     * @param array      $codeInfo
     * @param array      $postData
     *
     * @see https://tools.ietf.org/html/rfc7636#appendix-A
     *
     * @return void
     */
    private function verifyCodeVerifier(ClientInfo $clientInfo, array $codeInfo, array $postData)
    {
        // only for public clients
        if (null === $clientInfo->getSecret()) {
            if (!array_key_exists('code_verifier', $postData)) {
                throw new InvalidRequestException('missing "code_verifier" parameter');
            }

            // constant time compare of the code_challenge compared to the
            // expected value
            if (false === hash_equals(
                $codeInfo['code_challenge'],
                // https://github.com/paragonie/constant_time_encoding/issues/9
                // it's unknown if rtrim() is cache-timing-safe. This is fixed
                // in version 2.2 of paragonie/constant_time_encoding, but that
                // version requires php ^7, so we can't use it yet, we would
                // use Base64UrlSafe::encodeUnpadded then
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
            )) {
                throw new InvalidGrantException('invalid "code_verifier"');
            }
        }
    }

    /**
     * @param string $clientId
     *
     * @return ClientInfo
     */
    private function getClient($clientId)
    {
        if (false === $clientInfo = call_user_func($this->getClientInfo, $clientId)) {
            throw new InvalidClientException('client does not exist with this "client_id"');
        }

        return $clientInfo;
    }

    /**
     * @param array $data
     *
     * @return string
     */
    private function sign(array $data)
    {
        $jsonString = json_encode($data);
        if (false === $jsonString) {
            throw new ServerErrorException('unable to encode JSON');
        }

        return rtrim(
            Base64UrlSafe::encode(
                sodium_crypto_sign(
                    $jsonString,
                    sodium_crypto_sign_secretkey($this->keyPair)
                )
            ),
            '='
        );
    }

    /**
     * @param string $encodedSignedStr
     *
     * @return array
     */
    private function verify($encodedSignedStr)
    {
        // support old Base64 encoded strings as well...
        $encodedSignedStr = str_replace(['+', '/'], ['-', '_'], $encodedSignedStr);
        $signedStr = Base64UrlSafe::decode($encodedSignedStr);
        $str = sodium_crypto_sign_open($signedStr, sodium_crypto_sign_publickey($this->keyPair));
        if (false === $str) {
            throw new InvalidGrantException('invalid signature');
        }
        $codeTokenInfo = json_decode($str, true);
        if (null === $codeTokenInfo && JSON_ERROR_NONE !== json_last_error()) {
            throw new ServerErrorException('unable to decode JSON');
        }

        return $codeTokenInfo;
    }

    /**
     * @param DateInterval $dateInterval
     *
     * @return int
     */
    private function toExpiresIn(DateInterval $dateInterval)
    {
        return $this->dateTime->add($dateInterval)->getTimestamp() - $this->dateTime->getTimestamp();
    }
}
