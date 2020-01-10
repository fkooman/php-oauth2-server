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

namespace fkooman\OAuth\Server;

use fkooman\OAuth\Server\Exception\InsufficientScopeException;

class Scope
{
    /** @var string */
    private $scope;

    /**
     * @param string $scope
     */
    public function __construct($scope)
    {
        $this->scope = $scope;
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->scope;
    }

    /**
     * @param array<string> $requiredList
     *
     * @throws \fkooman\OAuth\Server\Exception\InsufficientScopeException
     *
     * @return void
     */
    public function requireAll(array $requiredList)
    {
        $grantedList = \explode(' ', $this->scope);
        foreach ($requiredList as $requiredScope) {
            if (!\in_array($requiredScope, $grantedList, true)) {
                throw new InsufficientScopeException(\sprintf('scope "%s" not granted', $requiredScope));
            }
        }
    }

    /**
     * @param array<string> $requiredList
     *
     * @throws \fkooman\OAuth\Server\Exception\InsufficientScopeException
     *
     * @return void
     */
    public function requireAny(array $requiredList)
    {
        $grantedList = \explode(' ', $this->scope);
        $hasAny = false;
        foreach ($requiredList as $requiredScope) {
            if (\in_array($requiredScope, $grantedList, true)) {
                $hasAny = true;
            }
        }

        if (!$hasAny) {
            throw new InsufficientScopeException(\sprintf('not any of scopes "%s" granted', \implode(' ', $requiredList)));
        }
    }
}
