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
use fkooman\OAuth\Server\TokenStorage;

try {
    // storage
    $tokenStorage = new TokenStorage(new PDO(sprintf('sqlite:%s/data/db.sqlite', dirname(__DIR__))));
    $tokenStorage->init();

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
        $tokenStorage
    );

    // XXX take this from $_SERVER variable
    $userId = 'foo';

    switch ($_SERVER['REQUEST_METHOD']) {
        case 'GET':
            $authorizeVariables = $oauthServer->getAuthorize($_GET);
            http_response_code(200);
            echo sprintf('<html><head><title>Authorize</title></head><body><pre>%s</pre><form method="post"><button type="submit" name="approve" value="yes">Approve</button></form></body></html>', var_export($authorizeVariables, true));
            break;
        case 'POST':
            $redirectUri = $oauthServer->postAuthorize($_GET, $_POST, $userId);
            http_response_code(302);
            header(sprintf('Location: %s', $redirectUri));
            break;
        default:
            http_response_code(405);
            header('Allow: GET,POST');
            echo '[405] Method Not Allowed';
            break;
    }
} catch (OAuthException $e) {
    http_response_code($e->getCode());
    echo sprintf('[%d] %s (%s)', $e->getCode(), $e->getMessage(), $e->getDescription());
} catch (Exception $e) {
    http_response_code(500);
    echo sprintf('[500] %s', $e->getMessage());
}
