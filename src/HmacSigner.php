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
use TypeError;

class HmacSigner implements SignerInterface
{
    const HMAC_ALGO = 'sha256';

    /** @var SecretKey */
    private $secretKey;

    /**
     * @param SecretKey $secretKey
     */
    public function __construct(SecretKey $secretKey)
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
     * @param array $codeTokenInfo
     *
     * @return string
     */
    public function sign(array $codeTokenInfo)
    {
        $tokenPayload = Base64UrlSafe::encodeUnpadded(Json::encode($codeTokenInfo));
        $keyId = $this->secretKey->getKeyId();
        $tokenSignature = Base64UrlSafe::encodeUnpadded($this->__sign($tokenPayload.$keyId));

        return $tokenPayload.'.'.$keyId.'.'.$tokenSignature;
    }

    /**
     * @param string $codeTokenString
     *
     * @return false|array
     */
    public function verify($codeTokenString)
    {
        if (!\is_string($codeTokenString)) {
            throw new TypeError('argument 1 must be string');
        }
        $codeTokenParts = \explode('.', $codeTokenString);
        if (3 !== \count($codeTokenParts)) {
            // invalid token, it MUST contain a "."
            return false;
        }

        $tokenSignature = Base64UrlSafe::encodeUnpadded($this->__sign($codeTokenParts[0].$codeTokenParts[1]));
        if (false === \hash_equals($tokenSignature, $codeTokenParts[2])) {
            return false;
        }

        $codeTokenInfo = Json::decode(Base64UrlSafe::decode($codeTokenParts[0]));
        $codeTokenInfo['key_id'] = $codeTokenParts[1];

        return $codeTokenInfo;
    }
}
