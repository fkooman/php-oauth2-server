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

use LengthException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;

class JwtSigner implements SignerInterface
{
    const JWT_ALGO = 'HS256';

    const HMAC_ALGO = 'sha256';

    // strlen(hash('sha256', '', true))
    const KEY_LENGTH_BYTES = 32;

    /** @var string */
    private $secretKey;

    /**
     * @param string $secretKey
     */
    public function __construct($secretKey)
    {
        if (self::KEY_LENGTH_BYTES !== Binary::safeStrlen($secretKey)) {
            throw new LengthException('invalid key length');
        }
        $this->secretKey = $secretKey;
    }

    /**
     * @param string $payloadStr
     *
     * @return string
     */
    private function __sign($payloadStr)
    {
        return \hash_hmac(self::HMAC_ALGO, $payloadStr, $this->secretKey, true);
    }

    /**
     * @param array<string,mixed> $codeTokenInfo
     *
     * @return string
     */
    public function sign(array $codeTokenInfo)
    {
        $jwtHeader = Base64UrlSafe::encodeUnpadded(
            Json::encode(
                [
                    'alg' => self::JWT_ALGO,
                    'typ' => 'JWT',
                ]
            )
        );
        $jwtPayload = Base64UrlSafe::encodeUnpadded(Json::encode($codeTokenInfo));
        $jwtSignature = Base64UrlSafe::encodeUnpadded($this->__sign($jwtHeader.'.'.$jwtPayload));

        return $jwtHeader.'.'.$jwtPayload.'.'.$jwtSignature;
    }

    /**
     * @param string $codeTokenString
     *
     * @return false|array<string,mixed>
     */
    public function verify($codeTokenString)
    {
        $jwtParts = \explode('.', $codeTokenString);
        if (3 !== \count($jwtParts)) {
            // invalid token, it MUST contain two dots
            return false;
        }

        $jwtSignature = Base64UrlSafe::encodeUnpadded($this->__sign($jwtParts[0].'.'.$jwtParts[1]));
        if (false === \hash_equals($jwtSignature, $jwtParts[2])) {
            return false;
        }

        return Json::decode(Base64UrlSafe::decode($jwtParts[1]));
    }
}
