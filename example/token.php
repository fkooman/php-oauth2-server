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

require_once \dirname(__DIR__).'/vendor/autoload.php';
require_once __DIR__.'/client_info.php';
$baseDir = \dirname(__DIR__);

use fkooman\Jwt\Keys\PrivateKey;
use fkooman\Jwt\Keys\PublicKey;
use fkooman\Jwt\RS256;
use fkooman\OAuth\Server\ClientInfo;
use fkooman\OAuth\Server\Exception\OAuthException;
use fkooman\OAuth\Server\Http\JsonResponse;
use fkooman\OAuth\Server\OAuthServer;
use fkooman\OAuth\Server\OpenId;
use fkooman\OAuth\Server\SodiumSigner;
use fkooman\OAuth\Server\Storage;

try {
    // persistent storage for access_token authorizations
    $storage = new Storage(new PDO(\sprintf('sqlite:%s/data/db.sqlite', $baseDir)));
    $storage->init();

    $oauthServer = new OAuthServer(
        $storage,
        // getClientInfo is a callback to "convert" a client_id into a
        // ClientInfo object, typically this configuration comes from a
        // configuration file or database, here we use a static file
        'getClientInfo',
        new SodiumSigner(
            // see README on how to generate a "server.key"
            \file_get_contents('server.key')
        )
    );

    // expire access_token after 30 seconds, and refresh_token after 5 minutes
    // DEFAULT: 1 hour / 180 days
    $oauthServer->setAccessTokenExpiry(new DateInterval('PT30S'));
    $oauthServer->setRefreshTokenExpiry(new DateInterval('PT5M'));

    $oauthServer->enableOpenId(
        new OpenId(
            'http://localhost:8080',
            new RS256(
                PublicKey::load('rsa.pub'),
                PrivateKey::load('rsa.key')
            )
        )
    );

    switch ($_SERVER['REQUEST_METHOD']) {
        case 'POST':
            // here we obtain the "Basic Authentication" user and pass
            $authUser = \array_key_exists('PHP_AUTH_USER', $_SERVER) ? $_SERVER['PHP_AUTH_USER'] : null;
            $authPass = \array_key_exists('PHP_AUTH_PW', $_SERVER) ? $_SERVER['PHP_AUTH_PW'] : null;
            $jsonResponse = $oauthServer->postToken($_POST, $authUser, $authPass);

            // we print the HTTP response to the "error_log" for easy debugging
            \error_log(\var_export($jsonResponse, true));
            $jsonResponse->send();
            break;
        default:
            // typically your HTTP framework would take care of this, but here
            // in "plain" PHP we have to take care of it...
            $jsonResponse = new JsonResponse(
                [
                    'error' => 'invalid_request',
                    'error_description' => 'Method Not Allowed',
                ],
                [
                    'Allow' => 'POST',
                ],
                405
            );
            \error_log(\var_export($jsonResponse, true));
            $jsonResponse->send();
    }
} catch (OAuthException $e) {
    // the Exception also contains a JsonResponse, like above
    $jsonResponse = $e->getJsonResponse();
    \error_log(\var_export($jsonResponse, true));
    $jsonResponse->send();
} catch (Exception $e) {
    // typically your HTTP framework would take care of this, but here
    // in "plain" PHP we have to take care of it... here we catch all
    // "internal server" errors
    $jsonResponse = new JsonResponse(
        [
            'error' => 'server_error',
            'error_description' => $e->getMessage(),
        ],
        [],
        500
    );
    \error_log(\var_export($jsonResponse, true));
    $jsonResponse->send();
}
