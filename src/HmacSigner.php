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

class HmacSigner implements SignerInterface
{
    const HMAC_ALGO = 'sha256';

    /** @var HmacKey */
    private $secretKey;

    /**
     * @param HmacKey $secretKey
     */
    public function __construct(HmacKey $secretKey)
    {
        $this->secretKey = $secretKey;
    }

    /**
     * @param string $payloadStr
     *
     * @return string
     */
    private function __sign($payloadStr)
    {
        return \hash_hmac(self::HMAC_ALGO, $payloadStr, $this->secretKey->raw(), true);
    }

    /**
     * @param array<string,mixed> $codeTokenInfo
     *
     * @return string
     */
    public function sign(array $codeTokenInfo)
    {
        $tokenPayload = Base64UrlSafe::encodeUnpadded(Json::encode($codeTokenInfo));
        $tokenSignature = Base64UrlSafe::encodeUnpadded($this->__sign($tokenPayload));

        return $tokenPayload.'.'.$tokenSignature;
    }

    /**
     * @param string $codeTokenString
     *
     * @return false|array<string,mixed>
     */
    public function verify($codeTokenString)
    {
        $codeTokenParts = \explode('.', $codeTokenString);
        if (2 !== \count($codeTokenParts)) {
            // invalid token, it MUST contain a "."
            return false;
        }

        $tokenSignature = Base64UrlSafe::encodeUnpadded($this->__sign($codeTokenParts[0]));
        if (false === \hash_equals($tokenSignature, $codeTokenParts[1])) {
            return false;
        }

        return Json::decode(Base64UrlSafe::decode($codeTokenParts[0]));
    }
}
