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

use fkooman\OAuth\Server\Exception\InvalidGrantException;
use fkooman\OAuth\Server\Exception\InvalidTokenException;
use fkooman\OAuth\Server\Exception\ServerErrorException;
use ParagonIE\ConstantTime\Base64UrlSafe;

class Util
{
    /**
     * @param mixed $jsonData
     *
     * @return string
     */
    public static function encodeJson($jsonData)
    {
        $jsonString = \json_encode($jsonData);
        if (false === $jsonString && JSON_ERROR_NONE !== \json_last_error()) {
            throw new ServerErrorException('unable to encode JSON');
        }

        return $jsonString;
    }

    /**
     * @param string $jsonString
     *
     * @return mixed
     */
    public static function decodeJson($jsonString)
    {
        $jsonData = \json_decode($jsonString, true);
        if (null === $jsonData && JSON_ERROR_NONE !== \json_last_error()) {
            throw new ServerErrorException('unable to decode JSON');
        }

        return $jsonData;
    }

    /**
     * @param string $redirectUri
     * @param array  $queryParameters
     *
     * @return string
     */
    public static function prepareRedirectUri($redirectUri, array $queryParameters)
    {
        return \sprintf(
            '%s%s%s',
            $redirectUri,
            false === \strpos($redirectUri, '?') ? '?' : '&',
            \http_build_query($queryParameters)
        );
    }

    /**
     * @param string $requiredType
     * @param string $providedType
     *
     * @return void
     */
    public static function requireType($requiredType, $providedType)
    {
        // make sure we have the required type
        if ($requiredType !== $providedType) {
            $errorMsg = \sprintf('expected "%s", got "%s"', $requiredType, $providedType);
            if ('access_token' === $requiredType) {
                throw new InvalidTokenException($errorMsg);
            }

            throw new InvalidGrantException($errorMsg);
        }
    }

    /**
     * @param string $str
     *
     * @return string
     */
    public static function toUrlSafeUnpadded($str)
    {
        // in earlier versions we supported standard Base64 encoding as well,
        // now we only generate Base64UrlSafe strings (without padding), but
        // we want to accept the old ones as well!
        return \str_replace(
            ['+', '/', '='],
            ['-', '_', ''],
            $str
        );
    }
}
