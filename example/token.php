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

    switch ($_SERVER['REQUEST_METHOD']) {
        case 'POST':
            $authUser = array_key_exists('PHP_AUTH_USER', $_SERVER) ? $_SERVER['PHP_AUTH_USER'] : null;
            $authPass = array_key_exists('PHP_AUTH_PW', $_SERVER) ? $_SERVER['PHP_AUTH_PW'] : null;

            http_response_code(200);
            header('Content-Type: application/json');
            header('Cache-Control: no-store');
            header('Pragma: no-cache');
            echo json_encode($oauthServer->postToken($_POST, $authUser, $authPass));
            break;
        default:
            http_response_code(405);
            header('Content-Type: application/json');
            header('Cache-Control: no-store');
            header('Pragma: no-cache');
            header('Allow: POST');
            echo json_encode(['error' => 'invalid_request', 'error_description' => 'Method Not Allowed']);
    }
} catch (OAuthException $e) {
    http_response_code($e->getCode());
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    header('Pragma: no-cache');
    if (401 === $e->getCode()) {
        header('WWW-Authenticate: Basic realm="OAuth"');
    }
    echo json_encode(['error' => $e->getMessage(), 'error_description' => $e->getDescription()]);
} catch (Exception $e) {
    http_response_code(500);
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    header('Pragma: no-cache');
    echo json_encode(['error' => 'server_error', 'error_description' => $e->getMessage()]);
}
