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

use fkooman\OAuth\Server\Exception\InsufficientScopeException;

class TokenInfo
{
    /** @var string */
    private $authKey;

    /** @var string */
    private $userId;

    /** @var string */
    private $clientId;

    /** @var string */
    private $scope;

    /** @var bool */
    private $isLocal;

    /** @var string */
    private $publicKey;

    /**
     * @param string $authKey
     * @param string $userId
     * @param string $clientId
     * @param string $scope
     * @param bool   $isLocal
     * @param string $publicKey
     */
    public function __construct($authKey, $userId, $clientId, $scope, $isLocal, $publicKey)
    {
        $this->authKey = $authKey;
        $this->userId = $userId;
        $this->clientId = $clientId;
        $this->scope = $scope;
        $this->isLocal = $isLocal;
        $this->publicKey = $publicKey;
    }

    /**
     * @return string
     */
    public function getAuthKey()
    {
        return $this->authKey;
    }

    /**
     * @return string
     */
    public function getUserId()
    {
        return $this->userId;
    }

    /**
     * @return string
     */
    public function getClientId()
    {
        return $this->clientId;
    }

    /**
     * @return string
     */
    public function getScope()
    {
        return $this->scope;
    }

    /**
     * @return bool
     */
    public function getIsLocal()
    {
        return $this->isLocal;
    }

    /**
     * @return string
     */
    public function getPublicKey()
    {
        return $this->publicKey;
    }

    /**
     * @param array $requiredScopeList
     *
     * @throws \fkooman\OAuth\Server\Exception\InsufficientScopeException
     *
     * @return void
     */
    public function requireAllScope(array $requiredScopeList)
    {
        $grantedScopeList = explode(' ', $this->scope);
        foreach ($requiredScopeList as $requiredScope) {
            if (!in_array($requiredScope, $grantedScopeList, true)) {
                throw new InsufficientScopeException(sprintf('scope "%s" not granted', $requiredScope));
            }
        }
    }

    /**
     * @param array $requiredScopeList
     *
     * @throws \fkooman\OAuth\Server\Exception\InsufficientScopeException
     *
     * @return void
     */
    public function requireAnyScope(array $requiredScopeList)
    {
        $grantedScopeList = explode(' ', $this->scope);
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
}
