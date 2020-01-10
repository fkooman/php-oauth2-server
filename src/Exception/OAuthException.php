<?php

/*
 * Copyright (c) 2017-2020 François Kooman <fkooman@tuxed.net>
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
use fkooman\OAuth\Server\Http\JsonResponse;

class OAuthException extends Exception
{
    /** @var string */
    private $description;

    /** @var array<string,string> */
    private $responseHeaders = [];

    /**
     * @param string               $message
     * @param string               $description
     * @param array<string,string> $responseHeaders
     * @param int                  $code
     */
    public function __construct($message, $description, array $responseHeaders = [], $code = 0, Exception $previous = null)
    {
        $this->description = $description;
        $this->responseHeaders = $responseHeaders;
        parent::__construct($message, $code, $previous);
    }

    /**
     * @return string
     */
    public function getDescription()
    {
        return $this->description;
    }

    /**
     * @return \fkooman\OAuth\Server\Http\JsonResponse
     */
    public function getJsonResponse()
    {
        return new JsonResponse(
            [
                'error' => $this->message,
                'error_description' => $this->description,
            ],
            $this->responseHeaders,
            $this->code
        );
    }
}
