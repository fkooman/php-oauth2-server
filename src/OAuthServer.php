<?php

/*
 * Copyright (c) 2017-2020 François Kooman <fkooman@tuxed.net>
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
    /** @var int */
    const TOKEN_VERSION = 5;

    /** @var StorageInterface */
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

    public function __construct(StorageInterface $storage, ClientDbInterface $clientDb, SignerInterface $signer)
    {
        $this->storage = $storage;
        $this->clientDb = $clientDb;
        $this->signer = $signer;
        $this->random = new Random();
        $this->dateTime = new DateTime();
        $this->accessTokenExpiry = new DateInterval('PT1H'); // 1 hour
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
     * @return void
     */
    public function setAccessTokenExpiry(DateInterval $accessTokenExpiry)
    {
        $this->accessTokenExpiry = $accessTokenExpiry;
    }

    /**
     * Validates the authorization request from the client and returns verified
     * data to show an authorization dialog.
     *
     * @param array<string,string> $getData
     *
     * @return array<string,string|null>
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
     * @param array<string,string> $getData
     * @param string               $userId
     *
     * @return Http\Response|false
     */
    public function getAuthorizeResponse(array $getData, $userId)
    {
        $clientInfo = $this->validateAuthorizeRequest($getData);
        if ($clientInfo->isApprovalRequired()) {
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
     * @param array<string,string> $getData
     * @param array<string,string> $postData
     * @param string               $userId
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

        // return authorization code
        $authorizationCode = $this->getAuthorizationCode(
            $userId,
            $getData['client_id'],
            $getData['scope'],
            $getData['redirect_uri'],
            $authKey,
            $getData['code_challenge']
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
     * @param array<string,string> $postData
     * @param string|null          $authUser BasicAuth user in case of secret client, null if public client
     * @param string|null          $authPass BasicAuth pass in case of secret client, null if public client
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
     * @return bool
     */
    public static function checkTokenVersion(array $tokenInfo)
    {
        // check version
        if (!\array_key_exists('v', $tokenInfo)) {
            return false;
        }
        if (self::TOKEN_VERSION !== $tokenInfo['v']) {
            return false;
        }

        return true;
    }

    /**
     * Validate the request to the "/authorize" endpoint.
     *
     * @param array<string,string> $getData
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

        return $clientInfo;
    }

    /**
     * @param array<string,string> $postData
     * @param string|null          $authUser BasicAuth user in case of secret client, null if public client
     * @param string|null          $authPass BasicAuth pass in case of secret client, null if public client
     *
     * @return JsonResponse
     */
    private function postTokenAuthorizationCode(array $postData, $authUser, $authPass)
    {
        $clientInfo = $this->getClient($postData['client_id']);
        $this->verifyClientCredentials($postData['client_id'], $clientInfo, $authUser, $authPass);

        // verify the authorization code signature
        if (false === $authorizationCodeInfo = $this->signer->verify($postData['code'])) {
            throw new InvalidGrantException('"authorization_code" has invalid signature');
        }

        // check version
        if (false === self::checkTokenVersion($authorizationCodeInfo)) {
            throw new InvalidGrantException('"authorization_code" has wrong version');
        }

        // make sure we got an authorization_code
        if ('authorization_code' !== $authorizationCodeInfo['type']) {
            throw new InvalidGrantException(\sprintf('expected "authorization_code", got "%s"', $authorizationCodeInfo['type']));
        }

        // check authorization_code expiry
        $expiresAt = new DateTime($authorizationCodeInfo['expires_at']);
        if ($this->dateTime->getTimestamp() >= $expiresAt->getTimestamp()) {
            throw new InvalidGrantException('"authorization_code" expired');
        }

        // parameters in POST body need to match the parameters stored with
        // the code
        $this->verifyAuthorizationCodeInfo($postData, $authorizationCodeInfo);

        // verify code_verifier
        $this->verifyCodeVerifier($authorizationCodeInfo, $postData);

        // check whether authorization_code was already used
        if ($this->storage->hasAuthorization($authorizationCodeInfo['auth_key'])) {
            $this->storage->deleteAuthorization($authorizationCodeInfo['auth_key']);

            throw new InvalidGrantException('"authorization_code" was used before');
        }

        // store the authorization
        $this->storage->storeAuthorization(
            $authorizationCodeInfo['user_id'],
            $authorizationCodeInfo['client_id'],
            $authorizationCodeInfo['scope'],
            $authorizationCodeInfo['auth_key']
        );

        $accessToken = $this->getAccessToken(
            $authorizationCodeInfo['user_id'],
            $postData['client_id'],
            $authorizationCodeInfo['scope'],
            $authorizationCodeInfo['auth_key']
        );

        $refreshToken = $this->getRefreshToken(
            $authorizationCodeInfo['user_id'],
            $postData['client_id'],
            $authorizationCodeInfo['scope'],
            $authorizationCodeInfo['auth_key']
        );

        return new JsonResponse(
            [
                'access_token' => $accessToken,
                'refresh_token' => $refreshToken,
                'token_type' => 'bearer',
                'expires_in' => $this->accessTokenExpiryAsInt(),
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
     * @param array<string,string> $postData
     * @param string|null          $authUser BasicAuth user in case of secret client, null if public client
     * @param string|null          $authPass BasicAuth pass in case of secret client, null if public client
     *
     * @return JsonResponse
     */
    private function postTokenRefreshToken(array $postData, $authUser, $authPass)
    {
        // verify the refresh code signature
        if (false === $refreshTokenInfo = $this->signer->verify($postData['refresh_token'])) {
            throw new InvalidGrantException('"refresh_token" has invalid signature');
        }

        // check version
        if (false === self::checkTokenVersion($refreshTokenInfo)) {
            throw new InvalidGrantException('"refresh_token" has wrong version');
        }

        // make sure we got a refresh_token
        if ('refresh_token' !== $refreshTokenInfo['type']) {
            throw new InvalidGrantException(\sprintf('expected "refresh_token", got "%s"', $refreshTokenInfo['type']));
        }

        $clientInfo = $this->getClient($refreshTokenInfo['client_id']);
        $this->verifyClientCredentials($refreshTokenInfo['client_id'], $clientInfo, $authUser, $authPass);

        // scope in POST body MUST match scope stored in the refresh_token when
        // provided
        if (\array_key_exists('scope', $postData)) {
            if ($postData['scope'] !== $refreshTokenInfo['scope']) {
                throw new InvalidRequestException('unexpected "scope"');
            }
        }

        // make sure the authorization still exists
        if (!$this->storage->hasAuthorization($refreshTokenInfo['auth_key'])) {
            throw new InvalidGrantException('"refresh_token" is no longer authorized');
        }

        $accessToken = $this->getAccessToken(
            $refreshTokenInfo['user_id'],
            $refreshTokenInfo['client_id'],
            $refreshTokenInfo['scope'],
            $refreshTokenInfo['auth_key']
        );

        return new JsonResponse(
            [
                'access_token' => $accessToken,
                'token_type' => 'bearer',
                'expires_in' => $this->accessTokenExpiryAsInt(),
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
     * @param string $scope
     * @param string $authKey
     *
     * @return string
     */
    private function getAccessToken($userId, $clientId, $scope, $authKey)
    {
        $expiresAt = clone $this->dateTime;
        $expiresAt->add($this->accessTokenExpiry);

        // for prevention of replays of authorization codes and the revocation
        // of access tokens when an authorization code is replayed, we use the
        // "auth_key" as a tag for the issued access tokens
        return $this->signer->sign(
            [
                'v' => self::TOKEN_VERSION,
                'type' => 'access_token',
                'auth_key' => $authKey, // to bind it to the authorization
                'user_id' => $userId,
                'client_id' => $clientId,
                'scope' => $scope,
                'expires_at' => $expiresAt->format(DateTime::ATOM),
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
        return $this->signer->sign(
            [
                'v' => self::TOKEN_VERSION,
                'type' => 'refresh_token',
                'auth_key' => $authKey, // to bind it to the authorization
                'user_id' => $userId,
                'client_id' => $clientId,
                'scope' => $scope,
            ]
        );
    }

    /**
     * @param string $userId
     * @param string $clientId
     * @param string $scope
     * @param string $redirectUri
     * @param string $authKey
     * @param string $codeChallenge
     *
     * @return string
     */
    private function getAuthorizationCode($userId, $clientId, $scope, $redirectUri, $authKey, $codeChallenge)
    {
        // authorization codes expire after 5 minutes
        $expiresAt = clone $this->dateTime;
        $expiresAt->add(new DateInterval('PT5M'));

        // The PKCE RFC (7636) says: "The server MUST NOT include the
        // "code_challenge" value in client requests in a form that other
        // entities can extract." We assume this is only relevant for the
        // "code_challenge_method" "plain" and not "S256". We only support
        // "S256" and never "plain".
        return $this->signer->sign(
            [
                'v' => self::TOKEN_VERSION,
                'type' => 'authorization_code',
                'auth_key' => $authKey,
                'user_id' => $userId,
                'client_id' => $clientId,
                'scope' => $scope,
                'redirect_uri' => $redirectUri,
                'code_challenge' => $codeChallenge,
                'expires_at' => $expiresAt->format(DateTime::ATOM),
            ]
        );
    }

    /**
     * @param array<string,string> $postData
     * @param array<string,mixed>  $authorizationCodeInfo
     *
     * @return void
     */
    private function verifyAuthorizationCodeInfo(array $postData, array $authorizationCodeInfo)
    {
        if ($postData['client_id'] !== $authorizationCodeInfo['client_id']) {
            throw new InvalidRequestException('unexpected "client_id"');
        }

        if ($postData['redirect_uri'] !== $authorizationCodeInfo['redirect_uri']) {
            throw new InvalidRequestException('unexpected "redirect_uri"');
        }
    }

    /**
     * @param string      $clientId
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
     * @param array<string,mixed>  $authorizationCodeInfo
     * @param array<string,string> $postData
     *
     * @see https://tools.ietf.org/html/rfc7636#appendix-A
     *
     * @return void
     */
    private function verifyCodeVerifier(array $authorizationCodeInfo, array $postData)
    {
        // in >= 5.1.0 we ALWAYS require PKCE. In case clients do NOT support
        // PKCE they will fail anyway due to missing authorize/token
        // parameters regarding PKCE and never reach this point. Confidential
        // clients that DO support PKCE will keep working nicely, but in
        // addition now their code verifier is checked as well...
        $strCmp = \hash_equals(
            $authorizationCodeInfo['code_challenge'],
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
     * @return int
     */
    private function accessTokenExpiryAsInt()
    {
        $expiresAt = clone $this->dateTime;
        $expiresAt->add($this->accessTokenExpiry);

        return (int) ($expiresAt->getTimestamp() - $this->dateTime->getTimestamp());
    }

    /**
     * @param string               $redirectUri
     * @param array<string,string> $queryParameters
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
