<?php

/**
 * Copyright (c) 2017 François Kooman <fkooman@tuxed.net>.
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
use fkooman\OAuth\Server\Exception\BearerException;
use ParagonIE\ConstantTime\Base64;

/**
 * In addition to verifying the public key of the Bearer token, this will also
 * check the (local) database to see if the authorization is still there. This
 * is done as to avoid the window where a token is still valid (according to
 * its internal "expires_at" field) but the user already revoked the
 * authorization.
 */
class BearerLocalValidator extends BearerValidator
{
    /** @var Storage */
    private $storage;

    /**
     * @param string         $keyPair
     * @param Storage        $storage
     * @param \DateTime|null $dateTime
     */
    public function __construct($keyPair, Storage $storage, DateTime $dateTime = null)
    {
        $this->storage = $storage;
        $publicKey = Base64::encode(\Sodium\crypto_sign_publickey(Base64::decode($keyPair)));
        parent::__construct([$publicKey], $dateTime);
    }

    /**
     * @param string $authorizationHeader
     *
     * @return array
     */
    public function validate($authorizationHeader)
    {
        $tokenInfo = parent::validate($authorizationHeader);
        // validate in DB
        if (!$this->storage->hasAuthorization($tokenInfo['auth_key'])) {
            throw new BearerException('authorization no longer exists, invalid token');
        }

        return $tokenInfo;
    }
}
