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
require_once sprintf('%s/vendor/autoload.php', dirname(__DIR__));

use fkooman\OAuth\Server\ClientInfo;
use fkooman\OAuth\Server\Exception\OAuthException;
use fkooman\OAuth\Server\Http\AuthorizeResponse;
use fkooman\OAuth\Server\OAuthServer;
use fkooman\OAuth\Server\Storage;

try {
    // storage
    $storage = new Storage(new PDO(sprintf('sqlite:%s/data/db.sqlite', dirname(__DIR__))));
    $storage->init();

    // client "database"
    $getClientInfo = function ($clientId) {
        $oauthClients = require 'clients.php';
        if (!array_key_exists($clientId, $oauthClients)) {
            return false;
        }

        return new ClientInfo($oauthClients[$clientId]);
    };

    // server
    $oauthServer = new OAuthServer(
        $storage,
        $getClientInfo,
        '2y5vJlGqpjTzwr3Ym3UqNwJuI1BKeLs53fc6Zf84kbYcP2/6Ar7zgiPS6BL4bvCaWN4uatYfuP7Dj/QvdctqJRw/b/oCvvOCI9LoEvhu8JpY3i5q1h+4/sOP9C91y2ol'
    );

    // expire a token after 30 seconds
    $oauthServer->setExpiresIn(30);

    // XXX use user authentication information
    $userId = 'foo';

    switch ($_SERVER['REQUEST_METHOD']) {
        case 'GET':
            $authorizeVariables = $oauthServer->getAuthorize($_GET);
            $authorizeResponse = new AuthorizeResponse(
                sprintf('<html><head><title>Authorize</title></head><body><pre>%s</pre><form method="post"><button type="submit" name="approve" value="yes">Approve</button></form></body></html>', var_export($authorizeVariables, true))
            );
            $authorizeResponse->send();
            break;
        case 'POST':
            $authorizeResponse = $oauthServer->postAuthorize($_GET, $_POST, $userId);
            $authorizeResponse->send();
            break;
        default:
            $authorizeResponse = new AuthorizeResponse('[405] Method Not Allowed', ['Allow' => 'GET,POST'], 405);
            $authorizeResponse->send();
    }
} catch (OAuthException $e) {
    $e->getAuthorizeResponse()->send();
} catch (Exception $e) {
    $authorizeResponse = new AuthorizeResponse(
        sprintf('[500] %s', $e->getMessage()),
        [],
        500
    );
    $authorizeResponse->send();
}
