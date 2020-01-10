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

require_once \dirname(__DIR__).'/vendor/autoload.php';
$baseDir = \dirname(__DIR__);

use fkooman\OAuth\Server\Http\Response;
use fkooman\OAuth\Server\PdoStorage;

try {
    // persistent storage for access_token authorizations
    $storage = new PdoStorage(new PDO(\sprintf('sqlite:%s/data/db.sqlite', $baseDir)));
    $storage->init();

    // user authentication MUST take place, here we ignore this for simplicity,
    // and assume the user_id is "foo"
    $userId = 'foo';

    // get all authorizations for this user
    echo '<html><head><title>Revoke</title></head><body><ul>';
    foreach ($storage->getAuthorizations($userId) as $authorization) {
        echo \sprintf(
            '<li>deleting authorization for user "%s", client "%s" and scope "%s"</li>',
            $userId,
            $authorization['client_id'],
            $authorization['scope']
        );
        $storage->deleteAuthorization($authorization['auth_key']);
    }
    echo '</ul></body></html>';
} catch (Exception $e) {
    // typically your HTTP framework would take care of this, but here
    // in "plain" PHP we have to take care of it... here we catch all
    // "internal server" errors
    $httpResponse = new Response(
        \sprintf('[500] %s', $e->getMessage()),
        ['Content-Type' => 'text/html'],
        500
    );
    $httpResponse->send();
}
