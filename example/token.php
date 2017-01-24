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

use fkooman\OAuth\Server\Exception\TokenException;
use fkooman\OAuth\Server\OAuthServer;
use fkooman\OAuth\Server\Random;
use fkooman\OAuth\Server\TokenStorage;

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
    $tokenStorage,
    new Random(),
    new DateTime(),
    $getClientInfo
);

if ('POST' !== $_SERVER['REQUEST_METHOD']) {
    http_response_code(405);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'only POST is allowed to this endpoint']);
    exit(1);
}

$authUser = array_key_exists('PHP_AUTH_USER', $_SERVER) ? $_SERVER['PHP_AUTH_USER'] : null;
$authPass = array_key_exists('PHP_AUTH_PW', $_SERVER) ? $_SERVER['PHP_AUTH_PW'] : null;

try {
    $tokenResponse = $oauthServer->postToken($_POST, $authUser, $authPass);
} catch (TokenException $e) {
    $tokenResponse = $e->getResponse();
}

http_response_code($tokenResponse->getStatusCode());
foreach ($tokenResponse->getHeaders() as $k => $v) {
    header(sprintf('%s: %s', $k, $v));
}
echo $tokenResponse->getBody();
exit(0);
