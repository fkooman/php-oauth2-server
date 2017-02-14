<?php
/**
 *  Copyright (C) 2017 François Kooman <fkooman@tuxed.net>.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as
 *  published by the Free Software Foundation, either version 3 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
require_once sprintf('%s/vendor/autoload.php', dirname(__DIR__));

use fkooman\OAuth\Server\Exception\OAuthException;
use fkooman\OAuth\Server\OAuthServer;
use fkooman\OAuth\Server\Storage;

try {
    // storage
    $storage = new Storage(new PDO(sprintf('sqlite:%s/data/db.sqlite', dirname(__DIR__))));
    $storage->init();

    // client "database"
    $getClientInfo = function ($clientId) {
        $oauthClients = [
            'demo_client' => [
                'redirect_uri' => 'http://localhost:8081/callback.php',
                'response_type' => 'code',
                'display_name' => 'Demo Client',
                'client_secret' => 'demo_secret',
            ],
        ];

        if (!array_key_exists($clientId, $oauthClients)) {
            return false;
        }

        return $oauthClients[$clientId];
    };

    // server
    $oauthServer = new OAuthServer(
        $getClientInfo,
        base64_decode('2y5vJlGqpjTzwr3Ym3UqNwJuI1BKeLs53fc6Zf84kbYcP2/6Ar7zgiPS6BL4bvCaWN4uatYfuP7Dj/QvdctqJRw/b/oCvvOCI9LoEvhu8JpY3i5q1h+4/sOP9C91y2ol'),
        $storage
    );

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
            break;
    }
} catch (OAuthException $e) {
    http_response_code($e->getCode());
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    header('Pragma: no-cache');
    if (401 === $e->getCode()) {
        header('WWW-Authenticate: Basic realm="OAuth');
    }
    echo json_encode(['error' => $e->getMessage(), 'error_description' => $e->getDescription()]);
} catch (Exception $e) {
    http_response_code(500);
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    header('Pragma: no-cache');
    echo json_encode(['error' => 'server_error', 'error_description' => $e->getMessage()]);
}
