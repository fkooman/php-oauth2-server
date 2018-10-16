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

use InvalidArgumentException;

class CodeTokenInfo
{
    /** @var string */
    private $codeTokenType;

    /** @var string */
    private $authKey;

    /** @var string */
    private $userId;

    /** @var string */
    private $clientId;

    /** @var Scope */
    private $scope;

    /** @var null|string */
    private $keyId = null;

    /**
     * @param array $codeTokenInfo
     */
    public function __construct(array $codeTokenInfo)
    {
        foreach (['type', 'auth_key', 'user_id', 'client_id', 'scope'] as $k) {
            if (!\array_key_exists($k, $codeTokenInfo)) {
                throw new InvalidArgumentException('key missing');
            }
            if (!\is_string($codeTokenInfo[$k])) {
                throw new InvalidArgumentException(\sprintf('"%s" must be string', $k));
            }
        }
        $this->codeTokenType = $codeTokenInfo['type'];
        $this->authKey = $codeTokenInfo['auth_key'];
        $this->userId = $codeTokenInfo['user_id'];
        $this->clientId = $codeTokenInfo['client_id'];
        $this->scope = new Scope($codeTokenInfo['scope']);

        if (\array_key_exists('key_id', $codeTokenInfo)) {
            if (!\is_string($codeTokenInfo['key_id'])) {
                throw new InvalidArgumentException('must be string');
            }
            $this->keyId = $codeTokenInfo['key_id'];
        }
    }

    /**
     * @return string
     */
    public function getCodeTokenType()
    {
        return $this->codeTokenType;
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
     * @return Scope
     */
    public function getScope()
    {
        return $this->scope;
    }

    /**
     * @return null|string
     */
    public function getKeyId()
    {
        return $this->keyId;
    }
}
