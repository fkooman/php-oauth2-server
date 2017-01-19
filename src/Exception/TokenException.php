<?php
/**
 *  Copyright (C) 2016 François Kooman <fkooman@tuxed.net>.
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

namespace fkooman\OAuth\Server\Exception;

use Exception;
use fkooman\OAuth\Server\TokenResponse;

class TokenException extends OAuthException
{
    /** @var string */
    private $description;

    public function __construct($message, $description, $code = 0, Exception $previous = null)
    {
        $this->description = $description;
        parent::__construct($message, $code, $previous);
    }

    public function getDescription()
    {
        return $this->description;
    }

    public function getResponse()
    {
        $responseHeaders = [];
        if (401 === $this->code) {
            $responseHeaders = [
                'WWW-Authenticate' => sprintf('Bearer error=%s,error_description=%s', $this->message, $this->description),
            ];
        }

        return new TokenResponse(
            [
                'error' => $this->message,
                'error_description' => $this->description,
            ],
            $responseHeaders,
            $this->code
        );
    }
}
