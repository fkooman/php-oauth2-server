<?php
/**
 *  Copyright (C) 2017 François Kooman <fkooman@tuxed.net>.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as
 *  published by the Free Software Foundation, either version 3 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

namespace fkooman\OAuth\Server;

use DateTime;
use fkooman\OAuth\Server\Exception\BearerException;

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

    public function __construct($keyPair, Storage $storage, DateTime $dateTime = null)
    {
        $this->storage = $storage;
        $publicKey = \Sodium\crypto_sign_publickey($keyPair);
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
