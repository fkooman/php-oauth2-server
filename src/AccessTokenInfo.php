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

class AccessTokenInfo
{
    /** @var ResourceOwner */
    private $resourceOwner;

    /** @var string */
    private $clientId;

    /** @var Scope */
    private $scope;

    /** @var \DateTime */
    private $authzExpiresAt;

    /**
     * @param ResourceOwner $resourceOwner
     * @param string        $clientId
     * @param Scope         $scope
     * @param \DateTime     $authzExpiresAt
     */
    public function __construct(ResourceOwner $resourceOwner, $clientId, Scope $scope, DateTime $authzExpiresAt)
    {
        $this->resourceOwner = $resourceOwner;
        $this->clientId = $clientId;
        $this->scope = $scope;
        $this->authzExpiresAt = $authzExpiresAt;
    }

    /**
     * @return ResourceOwner
     */
    public function getResourceOwner()
    {
        return $this->resourceOwner;
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
     * @return \DateTime
     */
    public function getAuthzExpiresAt()
    {
        return $this->authzExpiresAt;
    }
}
