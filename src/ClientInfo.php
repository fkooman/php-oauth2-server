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

use RuntimeException;

class ClientInfo
{
    /** @var string|null */
    private $displayName = null;

    /** @var array */
    private $redirectUriList;

    /** @var string */
    private $responseType;

    /** @var string|null */
    private $clientSecret = null;

    /**
     * @param array $clientInfo
     */
    public function __construct(array $clientInfo)
    {
        if (!array_key_exists('redirect_uri', $clientInfo)) {
            throw new RuntimeException('"redirect_uri" not in client database');
        }
        $this->redirectUriList = (array) $clientInfo['redirect_uri'];

        if (!array_key_exists('response_type', $clientInfo)) {
            throw new RuntimeException('"response_type" not in client database');
        }
        $this->responseType = $clientInfo['response_type'];

        if (array_key_exists('display_name', $clientInfo)) {
            $this->displayName = $clientInfo['display_name'];
        }
        if (array_key_exists('client_secret', $clientInfo)) {
            $this->clientSecret = $clientInfo['client_secret'];
        }
    }

    /**
     * @return string|null
     */
    public function getDisplayName()
    {
        return $this->displayName;
    }

    /**
     * @return string
     */
    public function getResponseType()
    {
        return $this->responseType;
    }

    /**
     * @return string|null
     */
    public function getSecret()
    {
        return $this->clientSecret;
    }

    /**
     * @param string $redirectUri
     *
     * @return bool
     */
    public function isValidRedirectUri($redirectUri)
    {
        if (in_array($redirectUri, $this->redirectUriList, true)) {
            return true;
        }

        // parsing is NOT great... but don't see how to avoid it here, we need
        // to accept all ports and both IPv4 and IPv6 for loopback entries
        foreach ($this->redirectUriList as $clientRedirectUri) {
            if (0 === strpos($clientRedirectUri, 'http://127.0.0.1:{PORT}/')) {
                // IPv4
                if (self::portMatch($clientRedirectUri, $redirectUri)) {
                    return true;
                }
            }

            if (0 === strpos($clientRedirectUri, 'http://[::1]:{PORT}/')) {
                // IPv6
                if (self::portMatch($clientRedirectUri, $redirectUri)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @param string $clientRedirectUri
     * @param string $redirectUri
     *
     * @return bool
     */
    private static function portMatch($clientRedirectUri, $redirectUri)
    {
        // there should be a better way...
        if (false === $port = parse_url($redirectUri, PHP_URL_PORT)) {
            return false;
        }
        // only allow non-root ports
        if (!is_int($port) || 1024 > $port || 65535 < $port) {
            return false;
        }
        $clientRedirectUriWithPort = str_replace('{PORT}', (string) $port, $clientRedirectUri);

        return $redirectUri === $clientRedirectUriWithPort;
    }
}
