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

interface StorageInterface
{
    /**
     * @param string $authKey
     *
     * @return bool
     */
    public function logAuthKey($authKey);

    /**
     * @param string $authKey
     *
     * @return bool
     */
    public function hasAuthorization($authKey);

    /**
     * @param string $userId
     * @param string $clientId
     * @param string $scope
     * @param string $authKey
     *
     * @return void
     */
    public function storeAuthorization($userId, $clientId, $scope, $authKey);

    /**
     * @param string $userId
     *
     * @return array
     */
    public function getAuthorizations($userId);

    /**
     * @param string $authKey
     *
     * @return void
     */
    public function deleteAuthKey($authKey);

    /**
     * @param string $userId
     * @param string $clientId
     * @param string $scope
     *
     * @return void
     */
    public function deleteAuthorization($userId, $clientId, $scope);
}
