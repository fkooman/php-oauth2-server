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

try {
    if ('GET' === $_SERVER['REQUEST_METHOD']) {
        $authVars = $oauthServer->getAuthorize($_GET);
        echo sprintf('<html><head><title>Authorize</title></head><body><pre>%s</pre><form method="post"><button type="submit" name="approve" value="yes">Approve</button></form></body></html>', var_export($authVars, true));
        exit(0);
    }

    if ('POST' === $_SERVER['REQUEST_METHOD']) {
        http_response_code(302);
        header(sprintf('Location: %s', $oauthServer->postAuthorize($_GET, $_POST, 'foo')));
        exit(0);
    }
} catch (OAuthException $e) {
    error_log($e->getMessage());
    echo sprintf('ERROR: %s', $e->getMessage());
    exit(1);
}
