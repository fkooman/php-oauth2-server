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

/*
 * Compatibility layer for libsodium with namespace. We *require* PHP >= 7.2
 * sodium OR pecl-libsodium.
 *
 * Method PHPdoc inspired by paragonie/sodium_compat
 *
 * @see https://github.com/paragonie/sodium_compat
 */

if (!\defined('SODIUM_CRYPTO_SIGN_KEYPAIRBYTES')) {
    \define('SODIUM_CRYPTO_SIGN_KEYPAIRBYTES', \Sodium\CRYPTO_SIGN_KEYPAIRBYTES);
}

if (!\defined('SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES')) {
    \define('SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES', \Sodium\CRYPTO_SIGN_PUBLICKEYBYTES);
}

if (!\is_callable('sodium_crypto_sign_publickey')) {
    /**
     * @param string $keypair
     *
     * @return string
     */
    function sodium_crypto_sign_publickey($keypair)
    {
        return \Sodium\crypto_sign_publickey($keypair);
    }
}

if (!\is_callable('sodium_crypto_sign')) {
    /**
     * @param string $message
     * @param string $sk
     *
     * @return string
     */
    function sodium_crypto_sign($message, $sk)
    {
        return \Sodium\crypto_sign($message, $sk);
    }
}

if (!\is_callable('sodium_crypto_sign_secretkey')) {
    /**
     * @param string $keypair
     *
     * @return string
     */
    function sodium_crypto_sign_secretkey($keypair)
    {
        return \Sodium\crypto_sign_secretkey($keypair);
    }
}

if (!\is_callable('sodium_crypto_sign_open')) {
    /**
     * @param string $signedMessage
     * @param string $pk
     *
     * @return false|string
     */
    function sodium_crypto_sign_open($signedMessage, $pk)
    {
        return \Sodium\crypto_sign_open($signedMessage, $pk);
    }
}
