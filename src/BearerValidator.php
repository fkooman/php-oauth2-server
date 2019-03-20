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
use ParagonIE\ConstantTime\Binary;

class BearerValidator
{
    /** @var StorageInterface */
    private $storage;

    /** @var ClientDbInterface */
    private $clientDb;

    /** @var SignerInterface */
    private $signer;

    /** @var \DateTime */
    private $dateTime;

    /**
     * @param StorageInterface  $storage
     * @param ClientDbInterface $clientDb
     * @param SignerInterface   $verifier
     */
    public function __construct(StorageInterface $storage, ClientDbInterface $clientDb, SignerInterface $signer)
    {
        $this->storage = $storage;
        $this->clientDb = $clientDb;
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
     * @return AccessTokenInfo
     */
    public function validate($authorizationHeader)
    {
        SyntaxValidator::validateBearerToken($authorizationHeader);
        $providedToken = Binary::safeSubstr($authorizationHeader, 7);
        if (false === $accessTokenInfo = $this->signer->verify($providedToken)) {
            throw new InvalidTokenException('"access_token" has invalid signature');
        }

        // check version
        if (false === OAuthServer::checkTokenVersion($accessTokenInfo)) {
            throw new InvalidTokenException('"access_token" has wrong version');
        }

        // make sure we got an access_token
        if ('access_token' !== $accessTokenInfo['type']) {
            throw new InvalidTokenException(\sprintf('expected "access_token", got "%s"', $accessTokenInfo['type']));
        }

        // check access_token expiry
        if ($this->dateTime >= new DateTime($accessTokenInfo['expires_at'])) {
            throw new InvalidTokenException('"access_token" expired');
        }

        // the client MUST still be there
        if (false === $this->clientDb->get($accessTokenInfo['client_id'])) {
            throw new InvalidTokenException(\sprintf('client "%s" no longer registered', $accessTokenInfo['client_id']));
        }

        // the authorization MUST exist in the DB as well, otherwise it was
        // revoked...
        if (!$this->storage->hasAuthorization($accessTokenInfo['auth_key'])) {
            throw new InvalidTokenException(\sprintf('authorization for client "%s" no longer exists', $accessTokenInfo['client_id']));
        }

        return new AccessTokenInfo(
            ResourceOwner::fromEncodedString($accessTokenInfo['resource_owner']),
            $accessTokenInfo['client_id'],
            new Scope($accessTokenInfo['scope']),
            new DateTime($accessTokenInfo['authz_expires_at'])
        );
    }
}
