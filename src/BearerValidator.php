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

use DateTime;
use fkooman\OAuth\Server\Exception\InsufficientScopeException;
use fkooman\OAuth\Server\Exception\InvalidTokenException;

class BearerValidator
{
    /** @var Storage */
    private $storage;

    /** @var callable */
    private $getClientInfo;

    /** @var TokenSignerInterface */
    private $tokenSigner;

    /** @var \DateTime */
    private $dateTime;

    /**
     * @param Storage              $storage
     * @param callable             $getClientInfo
     * @param TokenSignerInterface $tokenSigner
     */
    public function __construct(Storage $storage, callable $getClientInfo, TokenSignerInterface $tokenSigner)
    {
        $this->storage = $storage;
        $this->getClientInfo = $getClientInfo;
        $this->tokenSigner = $tokenSigner;
        $this->dateTime = new DateTime();
    }

    /**
     * @param DateTime $dateTime
     *
     * @return void
     */
    public function setDateTime(DateTime $dateTime)
    {
        $this->dateTime = $dateTime;
    }

    /**
     * @param string $authorizationHeader
     *
     * @return TokenInfo
     */
    public function validate($authorizationHeader)
    {
        self::validateBearerCredentials($authorizationHeader);
        $providedToken = substr($authorizationHeader, 7);
        $listOfClaims = $this->tokenSigner->parse($providedToken);

        // type MUST be "access_token"
        if ('access_token' !== $listOfClaims['type']) {
            throw new InvalidTokenException('not an access token');
        }

        return new TokenInfo(
            $listOfClaims['auth_key'],
            $listOfClaims['user_id'],
            $listOfClaims['client_id'],
            $listOfClaims['scope'],
            new DateTime() // FIXME XXX what to use here? Do we really need to expose this?!
        );

        // as it is signed by us, the client MUST still be there
        if (false === call_user_func($this->getClientInfo, $tokenInfo->getClientId())) {
            throw new InvalidTokenException('client no longer registered');
        }

        // it MUST exist in the DB as well, otherwise it was revoked...
        if (!$this->storage->hasAuthorization($tokenInfo->getAuthKey())) {
            throw new InvalidTokenException('authorization for client no longer exists');
        }

        return $tokenInfo;
    }

    /**
     * @param TokenInfo $tokenInfo
     * @param array     $requiredScopeList
     *
     * @throws \fkooman\OAuth\Server\Exception\InsufficientScopeException
     *
     * @return void
     */
    public static function requireAllScope(TokenInfo $tokenInfo, array $requiredScopeList)
    {
        $grantedScopeList = explode(' ', $tokenInfo->getScope());
        foreach ($requiredScopeList as $requiredScope) {
            if (!in_array($requiredScope, $grantedScopeList, true)) {
                throw new InsufficientScopeException(sprintf('scope "%s" not granted', $requiredScope));
            }
        }
    }

    /**
     * @param TokenInfo $tokenInfo
     * @param array     $requiredScopeList
     *
     * @throws \fkooman\OAuth\Server\Exception\InsufficientScopeException
     *
     * @return void
     */
    public static function requireAnyScope(TokenInfo $tokenInfo, array $requiredScopeList)
    {
        $grantedScopeList = explode(' ', $tokenInfo->getScope());
        $hasAny = false;
        foreach ($requiredScopeList as $requiredScope) {
            if (in_array($requiredScope, $grantedScopeList, true)) {
                $hasAny = true;
            }
        }

        if (!$hasAny) {
            throw new InsufficientScopeException(sprintf('not any of scopes "%s" granted', implode(' ', $requiredScopeList)));
        }
    }

    /**
     * @param string $bearerCredentials
     *
     * @return void
     */
    private static function validateBearerCredentials($bearerCredentials)
    {
        // b64token    = 1*( ALPHA / DIGIT /
        //                   "-" / "." / "_" / "~" / "+" / "/" ) *"="
        // credentials = "Bearer" 1*SP b64token
        if (1 !== preg_match('|^Bearer [a-zA-Z0-9-._~+/]+=*$|', $bearerCredentials)) {
            throw new InvalidTokenException('bearer credential syntax error');
        }
    }
}
