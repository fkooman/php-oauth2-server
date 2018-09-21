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

namespace fkooman\OAuth\Server\Tests;

use fkooman\OAuth\Server\SignerInterface;
use fkooman\OAuth\Server\Util;
use ParagonIE\ConstantTime\Base64UrlSafe;

/**
 * Dummy "Signer", does not actually sign anything, just contains the data that
 * would be signed by an actual implementation.
 */
class TestSigner implements SignerInterface
{
    /**
     * @param array $listOfClaims
     *
     * @return string
     */
    public function sign(array $listOfClaims)
    {
        return Base64UrlSafe::encodeUnpadded(
            Util::encodeJson($listOfClaims)
        );
    }

    /**
     * @param string $inputTokenStr
     *
     * @return false|array
     */
    public function verify($inputTokenStr)
    {
        $jsonData = Util::decodeJson(
            Base64UrlSafe::decode($inputTokenStr)
        );

        // simulate an invalid signature
        if ('invalid_sig' === $jsonData['auth_key']) {
            return false;
        }

        $jsonData['key_id'] = 'local';

        return $jsonData;
    }
}
