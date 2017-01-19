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

namespace fkooman\OAuth\Server;

class TokenResponse
{
    /** @var array */
    private $responseData;

    /** @var array */
    private $responseHeaders;

    /** @var int */
    private $statusCode;

    public function __construct(array $responseData, array $responseHeaders = [], $statusCode = 200)
    {
        $this->statusCode = $statusCode;
        $this->responseData = $responseData;
        $this->responseHeaders = array_merge(
            [
                'Content-Type' => 'application/json',
                'Cache-Control' => 'no-store',
                'Pragma' => 'no-cache',
            ],
            $responseHeaders
        );
        $this->statusCode = $statusCode;
    }

    public function __toString()
    {
        return $this->getBody();
    }

    public function getBody($asArray = false)
    {
        if ($asArray) {
            return $this->responseData;
        }

        return json_encode($this->responseData);
    }

    public function getHeaders()
    {
        $responseHeaderList = [];
        foreach ($this->responseHeaders as $k => $v) {
            $responseHeaderList[] = sprintf('%s: %s', $k, $v);
        }

        return $responseHeaderList;
    }

    public function getStatusCode()
    {
        return $this->statusCode;
    }
}
