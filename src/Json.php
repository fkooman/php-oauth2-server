<?php

/*
 * Copyright (c) 2017-2020 François Kooman <fkooman@tuxed.net>
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

use fkooman\OAuth\Server\Exception\JsonException;

class Json
{
    /**
     * @param mixed $jsonData
     *
     * @return string
     */
    public static function encode($jsonData)
    {
        $jsonString = \json_encode($jsonData);
        // 5.5.0 	The return value on failure was changed from null string to FALSE.
        if (false === $jsonString || 'null' === $jsonString) {
            throw new JsonException(\sprintf('unable to encode JSON, error code "%d"', \json_last_error()));
        }

        return $jsonString;
    }

    /**
     * @param string $jsonString
     *
     * @return mixed
     */
    public static function decode($jsonString)
    {
        $jsonData = \json_decode($jsonString, true);
        if (null === $jsonData && JSON_ERROR_NONE !== \json_last_error()) {
            throw new JsonException(\sprintf('unable to decode JSON, error code "%d"', \json_last_error()));
        }

        return $jsonData;
    }
}
