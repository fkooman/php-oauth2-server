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

class ClientInfo
{
    /** @var string */
    private $clientId;

    /** @var array<string> */
    private $redirectUriList;

    /** @var string|null */
    private $clientSecret;

    /** @var string|null */
    private $displayName;

    /** @var bool */
    private $requireApproval;

    /**
     * @param string        $clientId
     * @param array<string> $redirectUriList
     * @param string|null   $clientSecret
     * @param string|null   $displayName
     * @param bool          $requireApproval
     */
    public function __construct($clientId, array $redirectUriList, $clientSecret, $displayName, $requireApproval)
    {
        $this->clientId = $clientId;
        $this->redirectUriList = $redirectUriList;
        $this->clientSecret = $clientSecret;
        $this->displayName = $displayName;
        $this->requireApproval = $requireApproval;
    }

    /**
     * @return string
     */
    public function getClientId()
    {
        return $this->clientId;
    }

    /**
     * @return string|null
     */
    public function getSecret()
    {
        return $this->clientSecret;
    }

    /**
     * @return string|null
     */
    public function getDisplayName()
    {
        return $this->displayName;
    }

    /**
     * @return bool
     */
    public function isApprovalRequired()
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
            // IPv4 loopback
            if (0 === \strpos($clientRedirectUri, 'http://127.0.0.1:{PORT}/')) {
                if (self::portMatch($clientRedirectUri, $redirectUri)) {
                    return true;
                }
            }

            // IPv6 loopback
            if (0 === \strpos($clientRedirectUri, 'http://[::1]:{PORT}/')) {
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
        $uriPort = \parse_url($redirectUri, PHP_URL_PORT);
        if (!\is_int($uriPort)) {
            return false;
        }

        // only allow non-root ports
        if (1024 > $uriPort || 65535 < $uriPort) {
            return false;
        }
        $clientRedirectUriWithPort = \str_replace('{PORT}', (string) $uriPort, $clientRedirectUri);

        return $redirectUri === $clientRedirectUriWithPort;
    }
}
