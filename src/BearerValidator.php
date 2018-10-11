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
    /** @var Storage */
    private $storage;

    /** @var ClientDbInterface */
    private $clientDb;

    /** @var SignerInterface */
    private $verifier;

    /** @var \DateTime */
    private $dateTime;

    /**
     * @param Storage           $storage
     * @param ClientDbInterface $clientDb
     * @param SignerInterface   $verifier
     */
    public function __construct(Storage $storage, ClientDbInterface $clientDb, SignerInterface $verifier)
    {
        $this->storage = $storage;
        $this->clientDb = $clientDb;
        $this->verifier = $verifier;
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
        $providedToken = Binary::safeSubstr($authorizationHeader, 7);
        $tokenData = $this->verifier->verify($providedToken);
        if (false === $tokenData) {
            throw new InvalidTokenException('"access_token" has invalid signature');
        }
        Util::requireType('access_token', $tokenData['type']);

        // check access_token expiry
        if ($this->dateTime >= new DateTime($tokenData['expires_at'])) {
            throw new InvalidTokenException('"access_token" expired');
        }

        $tokenInfo = new TokenInfo(
            $tokenData['auth_key'],
            $tokenData['user_id'],
            $tokenData['client_id'],
            $tokenData['scope']
        );

        // as it is signed by us, the client MUST still be there
        if (false === $this->clientDb->get($tokenInfo->getClientId())) {
            throw new InvalidTokenException(\sprintf('client "%s" no longer registered', $tokenInfo->getClientId()));
        }

        // it MUST exist in the DB as well, otherwise it was revoked...
        if (!$this->storage->hasAuthorization($tokenInfo->getAuthKey())) {
            throw new InvalidTokenException(\sprintf('authorization for client "%s" no longer exists', $tokenInfo->getClientId()));
        }

        return $tokenInfo;
    }
}
