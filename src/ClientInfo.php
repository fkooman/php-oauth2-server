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

use fkooman\OAuth\Server\Exception\ServerErrorException;

class ClientInfo
{
    /** @var string|null */
    private $displayName = null;

    /** @var array */
    private $redirectUriList;

    /** @var string|null */
    private $clientSecret = null;

    /** @var bool */
    private $requireApproval = true;

    /**
     * @param array $clientInfo
     */
    public function __construct(array $clientInfo)
    {
        if (!\array_key_exists('redirect_uri_list', $clientInfo)) {
            throw new ServerErrorException('"redirect_uri_list" not in client database');
        }
        if (!\is_array($clientInfo['redirect_uri_list'])) {
            throw new ServerErrorException('"redirect_uri_list" not an array');
        }
        $this->redirectUriList = $clientInfo['redirect_uri_list'];

        if (\array_key_exists('require_approval', $clientInfo)) {
            $this->requireApproval = (bool) $clientInfo['require_approval'];
        }
        if (\array_key_exists('display_name', $clientInfo)) {
            $this->displayName = $clientInfo['display_name'];
        }
        if (\array_key_exists('client_secret', $clientInfo)) {
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
     * @return string|null
     */
    public function getSecret()
    {
        return $this->clientSecret;
    }

    /**
     * @return bool
     */
    public function getRequireApproval()
    {
        return $this->requireApproval;
    }

    /**
     * @param string $redirectUri
     *
     * @return bool
     */
    public function isValidRedirectUri($redirectUri)
    {
        if (\in_array($redirectUri, $this->redirectUriList, true)) {
            return true;
        }

        // parsing is NOT great... but don't see how to avoid it here, we need
        // to accept all ports and both IPv4 and IPv6 for loopback entries
        foreach ($this->redirectUriList as $clientRedirectUri) {
            if (0 === \strpos($clientRedirectUri, 'http://127.0.0.1:{PORT}/')) {
                // IPv4
                if (self::portMatch($clientRedirectUri, $redirectUri)) {
                    return true;
                }
            }

            if (0 === \strpos($clientRedirectUri, 'http://[::1]:{PORT}/')) {
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
        if (false === $port = \parse_url($redirectUri, PHP_URL_PORT)) {
            return false;
        }
        // only allow non-root ports
        if (!\is_int($port) || 1024 > $port || 65535 < $port) {
            return false;
        }
        $clientRedirectUriWithPort = \str_replace('{PORT}', (string) $port, $clientRedirectUri);

        return $redirectUri === $clientRedirectUriWithPort;
    }
}
