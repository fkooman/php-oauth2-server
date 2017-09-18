<?php

/**
 * Copyright (c) 2017 François Kooman <fkooman@tuxed.net>.
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

/**
 * Class to work as a compatibility layer to support all versions of PHP
 * sodium integration out there.
 *
 * This class supports:
 * - PECL libsodium 1.x for older version of PHP (EPEL)
 * - PECL libsodium 2.x for PHP >= 7.0
 * - PHP sodium for PHP >= 7.2
 *
 * Method PHPdoc shamelessly taken from paragonie/sodium_compat
 *
 * @see https://github.com/paragonie/sodium_compat
 */
class SodiumCompat
{
    /**
     * @param string $keypair
     *
     * @return string
     */
    public static function crypto_sign_publickey($keypair)
    {
        if (is_callable('sodium_crypto_sign_publickey')) {
            return sodium_crypto_sign_publickey($keypair);
        }

        return \Sodium\crypto_sign_publickey($keypair);
    }

    /**
     * @param string $message
     * @param string $sk
     *
     * @return string
     */
    public static function crypto_sign($message, $sk)
    {
        if (is_callable('sodium_crypto_sign')) {
            return sodium_crypto_sign($message, $sk);
        }

        return \Sodium\crypto_sign($message, $sk);
    }

    /**
     * @param string $keypair
     *
     * @return string
     */
    public static function crypto_sign_secretkey($keypair)
    {
        if (is_callable('sodium_crypto_sign_secretkey')) {
            return sodium_crypto_sign_secretkey($keypair);
        }

        return \Sodium\crypto_sign_secretkey($keypair);
    }

    /**
     * @param string $signedMessage
     * @param string $pk
     *
     * @return false|string
     */
    public static function crypto_sign_open($signedMessage, $pk)
    {
        if (is_callable('sodium_crypto_sign_open')) {
            return sodium_crypto_sign_open($signedMessage, $pk);
        }

        return \Sodium\crypto_sign_open($signedMessage, $pk);
    }
}
