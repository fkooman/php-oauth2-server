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
use fkooman\OAuth\Server\Exception\InvalidTokenException;

class BearerValidator
{
    /** @var Storage */
    private $storage;

    /** @var callable */
    private $getClientInfo;

    /** @var SignerInterface */
    private $signer;

    /** @var \DateTime */
    private $dateTime;

    /**
     * @param Storage         $storage
     * @param callable        $getClientInfo
     * @param SignerInterface $signer
     */
    public function __construct(Storage $storage, callable $getClientInfo, SignerInterface $signer)
    {
        $this->storage = $storage;
        $this->getClientInfo = $getClientInfo;
        $this->signer = $signer;
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
        SyntaxValidator::validateBearerToken($authorizationHeader);
        $providedToken = substr($authorizationHeader, 7);
        $listOfClaims = $this->signer->verify($providedToken);
        OAuthServer::requireType('access_token', $listOfClaims['type']);

        $tokenInfo = new TokenInfo(
            $listOfClaims['auth_key'],
            $listOfClaims['user_id'],
            $listOfClaims['client_id'],
            $listOfClaims['scope']
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
}
