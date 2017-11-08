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

namespace fkooman\OAuth\Server\Exception;

use Exception;
use fkooman\OAuth\Server\Http\ApiResponse;

class BearerException extends OAuthException
{
    /**
     * @param string $message
     * @param int    $code
     */
    public function __construct($message, $code = 401, Exception $previous = null)
    {
        parent::__construct('invalid_token', $message, $code, $previous);
    }

    /**
     * @return \fkooman\OAuth\Server\Http\ApiResponse
     */
    public function getResponse()
    {
        $responseHeaders = [];
        if (401 === $this->getCode()) {
            $responseHeaders['WWW-Authenticate'] = sprintf(
                'Bearer error="%s",error_description="%s"',
                $this->getMessage(),
                $this->getDescription()
            );
        }

        return new ApiResponse(
            [
                'error' => $this->getMessage(),
                'error_description' => $this->getDescription(),
            ],
            $responseHeaders,
            $this->getCode()
        );
    }
}
