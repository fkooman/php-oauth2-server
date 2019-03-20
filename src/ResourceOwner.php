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

use ParagonIE\ConstantTime\Base64UrlSafe;

class ResourceOwner
{
    /** @var string */
    private $userId;

    /** @var string|null */
    private $extData;

    /**
     * @param string      $userId
     * @param string|null $extData
     */
    public function __construct($userId, $extData = null)
    {
        $this->userId = $userId;
        $this->extData = $extData;
    }

    /**
     * @return string
     */
    public function getUserId()
    {
        return $this->userId;
    }

    /**
     * @param string $extData
     *
     * @return void
     */
    public function setExtData($extData)
    {
        $this->extData = $extData;
    }

    /**
     * @return string|null
     */
    public function getExtData()
    {
        return $this->extData;
    }

    /**
     * @return string
     */
    public function encode()
    {
        return Base64UrlSafe::encodeUnpadded(
            Json::encode(
                [
                    'user_id' => $this->userId,
                    'ext_data' => $this->extData,
                ]
            )
        );
    }

    /**
     * @param string $encodedString
     *
     * @return self
     */
    public static function fromEncodedString($encodedString)
    {
        $userData = Json::decode(Base64UrlSafe::decode($encodedString));

        return new self($userData['user_id'], $userData['ext_data']);
    }
}
