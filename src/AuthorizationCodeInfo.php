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

use DateTime;
use fkooman\OAuth\Server\Exception\InvalidGrantException;
use InvalidArgumentException;

class AuthorizationCodeInfo extends CodeTokenInfo
{
    /** @var \DateTime */
    private $expiresAt;

    /** @var string */
    private $redirectUri;

    /** @var null|string */
    private $codeChallenge;

    /**
     * @param array $codeTokenInfo
     */
    public function __construct(array $codeTokenInfo)
    {
        parent::__construct($codeTokenInfo);

        if ('authorization_code' !== $this->getCodeTokenType()) {
            throw new InvalidGrantException(\sprintf('expected "authorization_code", got "%s"', $this->getCodeTokenType()));
        }

        if (!\is_string($codeTokenInfo['expires_at'])) {
            throw new InvalidArgumentException('must be string');
        }
        // enforce a certain datetime format?! XXX
        $this->expiresAt = new DateTime($codeTokenInfo['expires_at']);

        if (!\is_string($codeTokenInfo['redirect_uri'])) {
            throw new InvalidArgumentException('must be string');
        }
        $this->redirectUri = $codeTokenInfo['redirect_uri'];

        // XXX code challenge is also null when not public client?
        if (!\is_string($codeTokenInfo['code_challenge'])) {
            throw new InvalidArgumentException('must be string');
        }
        $this->codeChallenge = $codeTokenInfo['code_challenge'];
    }

    /**
     * @return \DateTime
     */
    public function getExpiresAt()
    {
        return $this->expiresAt;
    }

    /**
     * @return string
     */
    public function getRedirectUri()
    {
        return $this->redirectUri;
    }

    /**
     * @return null|string
     */
    public function getCodeChallenge()
    {
        return $this->codeChallenge;
    }
}
