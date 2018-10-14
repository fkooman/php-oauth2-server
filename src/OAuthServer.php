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
use fkooman\OAuth\Server\Exception\InvalidClientException;
use fkooman\OAuth\Server\Exception\InvalidGrantException;
use fkooman\OAuth\Server\Exception\InvalidRequestException;
use fkooman\OAuth\Server\Http\JsonResponse;
use fkooman\OAuth\Server\Http\RedirectResponse;
use ParagonIE\ConstantTime\Base64UrlSafe;

class OAuthServer
{
    /** @var Storage */
    private $storage;

    /** @var ClientDbInterface */
    private $clientDb;

    /** @var SignerInterface */
    private $signer;

    /** @var RandomInterface */
    private $random;

    /** @var \DateTime */
    private $dateTime;

    /** @var \DateInterval */
    private $accessTokenExpiry;

    /** @var null|\DateInterval */
    private $refreshTokenExpiry = null;

    /**
     * @param Storage           $storage
     * @param ClientDbInterface $clientDb
     * @param SignerInterface   $signer
     */
    public function __construct(Storage $storage, ClientDbInterface $clientDb, SignerInterface $signer)
    {
        $this->storage = $storage;
        $this->clientDb = $clientDb;
        $this->signer = $signer;
        $this->random = new Random();
        $this->dateTime = new DateTime();
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
        $this->dateTime = $dateTime;
    }

    /**
     * @param DateInterval $accessTokenExpiry
     *
     * @return void
     */
    public function setAccessTokenExpiry(DateInterval $accessTokenExpiry)
    {
        $this->accessTokenExpiry = $accessTokenExpiry;
    }

    /**
     * @param DateInterval $refreshTokenExpiry
     *
     * @return void
     */
    public function setRefreshTokenExpiry(DateInterval $refreshTokenExpiry)
    {
        $this->refreshTokenExpiry = $refreshTokenExpiry;
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
     * @return \fkooman\OAuth\Server\Http\RedirectResponse
     */
    public function postAuthorize(array $getData, array $postData, $userId)
    {
        $this->validateAuthorizeRequest($getData);
        RequestValidator::validateAuthorizePostParameters($postData);

        if ('no' === $postData['approve']) {
            // user did not approve, tell OAuth client
            return new RedirectResponse(
                self::prepareRedirectUri(
                    $getData['redirect_uri'],
                    [
                        'error' => 'access_denied',
                        'state' => $getData['state'],
                    ]
                )
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
            \array_key_exists('code_challenge', $getData) ? $getData['code_challenge'] : null
        );

        return new RedirectResponse(
            self::prepareRedirectUri(
                $getData['redirect_uri'],
                [
                    'code' => $authorizationCode,
                    'state' => $getData['state'],
                ]
            )
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

        // verify the authorization code signature
        $codeTokenInfo = $this->signer->verify($postData['code']);
        if (false === $codeTokenInfo) {
            throw new InvalidGrantException('"authorization_code" has invalid signature');
        }
        $authorizationCodeInfo = new AuthorizationCodeInfo(Json::decode($codeTokenInfo));

        // check authorization_code expiry
        if ($this->dateTime >= $authorizationCodeInfo->getExpiresAt()) {
            throw new InvalidGrantException('"authorization_code" expired');
        }

        // parameters in POST body need to match the parameters stored with
        // the code
        $this->verifyAuthorizationCodeInfo($postData, $authorizationCodeInfo);

        // verify code_verifier (iff public client)
        $this->verifyCodeVerifier($clientInfo, $authorizationCodeInfo, $postData);

        // 1. check if the authorization is still there
        if (false === $this->storage->hasAuthorization($authorizationCodeInfo->getAuthKey())) {
            throw new InvalidGrantException('"authorization_code" is no longer authorized');
        }

        // 2. make sure the authKey was not used before
        if (false === $this->storage->logAuthKey($authorizationCodeInfo->getAuthKey())) {
            // authKey was used before, delete authorization according to spec
            // so refresh_tokens and access_tokens can no longer be used
            $this->storage->deleteAuthKey($authorizationCodeInfo->getAuthKey());

            throw new InvalidGrantException('"authorization_code" reuse');
        }

        $accessToken = $this->getAccessToken(
            $authorizationCodeInfo->getUserId(),
            $postData['client_id'],
            $authorizationCodeInfo->getScope(),
            $authorizationCodeInfo->getAuthKey()
        );

        $refreshToken = $this->getRefreshToken(
            $authorizationCodeInfo->getUserId(),
            $postData['client_id'],
            $authorizationCodeInfo->getScope(),
            $authorizationCodeInfo->getAuthKey()
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
        // verify the refresh code signature
        $codeTokenInfo = $this->signer->verify($postData['refresh_token']);
        if (false === $codeTokenInfo) {
            throw new InvalidGrantException('"refresh_token" has invalid signature');
        }
        $refreshTokenInfo = new RefreshTokenInfo(Json::decode($codeTokenInfo));
        // check refresh_token expiry, refresh token expiry is OPTIONAL,
        // disable by default...
        if (null !== $refreshTokenInfo->getExpiresAt()) {
            if ($this->dateTime >= $refreshTokenInfo->getExpiresAt()) {
                throw new InvalidGrantException('"refresh_token" expired');
            }
        }

        $clientInfo = $this->getClient($refreshTokenInfo->getClientId());
        $this->verifyClientCredentials($refreshTokenInfo->getClientId(), $clientInfo, $authUser, $authPass);

        // parameters in POST body need to match the parameters stored with
        // the refresh token
        if ($postData['scope'] !== (string) $refreshTokenInfo->getScope()) {
            throw new InvalidRequestException('unexpected "scope"');
        }

        // make sure the authorization still exists
        if (!$this->storage->hasAuthorization($refreshTokenInfo->getAuthKey())) {
            throw new InvalidGrantException('"refresh_token" is no longer authorized');
        }

        $accessToken = $this->getAccessToken(
            $refreshTokenInfo->getUserId(),
            $refreshTokenInfo->getClientId(),
            $refreshTokenInfo->getScope(),
            $refreshTokenInfo->getAuthKey()
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
     * @param string $userId
     * @param string $clientId
     * @param Scope  $scope
     * @param string $authKey
     *
     * @return string
     */
    private function getAccessToken($userId, $clientId, Scope $scope, $authKey)
    {
        // for prevention of replays of authorization codes and the revocation
        // of access tokens when an authorization code is replayed, we use the
        // "auth_key" as a tag for the issued access tokens
        $expiresAt = \date_add(clone $this->dateTime, $this->accessTokenExpiry);

        return $this->signer->sign(
            Json::encode(
                [
                    'type' => 'access_token',
                    'auth_key' => $authKey, // to bind it to the authorization
                    'user_id' => $userId,
                    'client_id' => $clientId,
                    'scope' => (string) $scope,
                    'expires_at' => $expiresAt->format(DateTime::ATOM),
                ]
            )
        );
    }

    /**
     * @param string $userId
     * @param string $clientId
     * @param Scope  $scope
     * @param string $authKey
     *
     * @return string
     */
    private function getRefreshToken($userId, $clientId, Scope $scope, $authKey)
    {
        $refreshTokenInfo = [
            'type' => 'refresh_token',
            'auth_key' => $authKey, // to bind it to the authorization
            'user_id' => $userId,
            'client_id' => $clientId,
            'scope' => (string) $scope,
        ];

        if (null !== $this->refreshTokenExpiry) {
            $expiresAt = \date_add(clone $this->dateTime, $this->refreshTokenExpiry);
            $refreshTokenInfo['expires_at'] = $expiresAt->format(DateTime::ATOM);
        }

        return $this->signer->sign(
            Json::encode($refreshTokenInfo)
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
        $expiresAt = \date_add($this->dateTime, new DateInterval('PT5M'));

        // The PKCE RFC (7636) says: "The server MUST NOT include the
        // "code_challenge" value in client requests in a form that other
        // entities can extract." We assume this is only relevant for the
        // "code_challenge_method" "plain" and not "S256". We only support
        // "S256" and never "plain".
        return $this->signer->sign(
            Json::encode(
                [
                    'type' => 'authorization_code',
                    'auth_key' => $authKey,
                    'user_id' => $userId,
                    'client_id' => $clientId,
                    'scope' => $scope,
                    'redirect_uri' => $redirectUri,
                    'code_challenge' => $codeChallenge,
                    'expires_at' => $expiresAt->format(DateTime::ATOM),
                ]
            )
        );
    }

    /**
     * @param array                 $postData
     * @param AuthorizationCodeInfo $authorizationCodeInfo
     *
     * @return void
     */
    private function verifyAuthorizationCodeInfo(array $postData, AuthorizationCodeInfo $authorizationCodeInfo)
    {
        if ($postData['client_id'] !== $authorizationCodeInfo->getClientId()) {
            throw new InvalidRequestException('unexpected "client_id"');
        }

        if ($postData['redirect_uri'] !== $authorizationCodeInfo->getRedirectUri()) {
            throw new InvalidRequestException('unexpected "redirect_uri"');
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

            if (!\is_string($authPass)) {
                throw new InvalidClientException('invalid credentials (no authenticating pass)');
            }

            if (false === \hash_equals($clientSecret, $authPass)) {
                throw new InvalidClientException('invalid credentials (invalid authenticating pass)');
            }
        }
    }

    /**
     * @param ClientInfo            $clientInfo
     * @param AuthorizationCodeInfo $authorizationCodeInfo
     * @param array                 $postData
     *
     * @see https://tools.ietf.org/html/rfc7636#appendix-A
     *
     * @return void
     */
    private function verifyCodeVerifier(ClientInfo $clientInfo, AuthorizationCodeInfo $authorizationCodeInfo, array $postData)
    {
        // only for public clients
        if (null === $clientInfo->getSecret()) {
            if (!\array_key_exists('code_verifier', $postData)) {
                throw new InvalidRequestException('missing "code_verifier" parameter');
            }

            if (null === $codeChallenge = $authorizationCodeInfo->getCodeChallenge()) {
                // code_verifier not part of the codetoken?!
                // this is actually a malformed token! XXX
                throw new InvalidGrantException('invalid "code_verifier"');
            }

            // compare code_challenge with expected value
            $strCmp = \hash_equals(
                $codeChallenge,
                Base64UrlSafe::encodeUnpadded(
                    \hash(
                        'sha256',
                        $postData['code_verifier'],
                        true
                    )
                )
            );

            if (false === $strCmp) {
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
        if (false === $clientInfo = $this->clientDb->get($clientId)) {
            throw new InvalidClientException('client does not exist with this "client_id"');
        }

        return $clientInfo;
    }

    /**
     * @param DateInterval $dateInterval
     *
     * @return int
     */
    private function toExpiresIn(DateInterval $dateInterval)
    {
        return \date_add(clone $this->dateTime, $dateInterval)->getTimestamp() - $this->dateTime->getTimestamp();
    }

    /**
     * @param string $redirectUri
     * @param array  $queryParameters
     *
     * @return string
     */
    private static function prepareRedirectUri($redirectUri, array $queryParameters)
    {
        return \sprintf(
            '%s%s%s',
            $redirectUri,
            false === \strpos($redirectUri, '?') ? '?' : '&',
            \http_build_query($queryParameters)
        );
    }
}
