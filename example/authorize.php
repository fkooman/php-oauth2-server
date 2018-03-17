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

$baseDir = dirname(__DIR__);
/** @psalm-suppress UnresolvableInclude */
require_once sprintf('%s/vendor/autoload.php', $baseDir);

use fkooman\OAuth\Server\ClientInfo;
use fkooman\OAuth\Server\Exception\OAuthException;
use fkooman\OAuth\Server\Http\Response;
use fkooman\OAuth\Server\OAuthServer;
use fkooman\OAuth\Server\SodiumSigner;
use fkooman\OAuth\Server\Storage;

try {
    // persistent storage for access_token authorizations
    $storage = new Storage(new PDO(sprintf('sqlite:%s/data/db.sqlite', $baseDir)));
    $storage->init();

    // callback to "convert" a client_id into a ClientInfo object, typically
    // this configuration comes from a configuration file or database...
    $getClientInfo = function ($clientId) {
        $oauthClients = [
            // we only have one client here with client_id "demo_client"...
            'demo_client' => [
                'redirect_uri_list' => ['http://localhost:8081/callback.php'],
                'display_name' => 'Demo Client',
                'client_secret' => 'demo_secret',
                //'require_approval' => false,
            ],
        ];

        // if the client with this client_id does not exist, we return false...
        if (!array_key_exists($clientId, $oauthClients)) {
            return false;
        }

        return new ClientInfo($oauthClients[$clientId]);
    };

    $oauthServer = new OAuthServer(
        $storage,
        $getClientInfo,
        new SodiumSigner(
            // see README on how to generate a "server.key"
            file_get_contents('server.key')
        )
    );

    // expire access_token after 30 seconds, and refresh_token after 5 minutes
    // DEFAULT: 1 hour / 180 days
    $oauthServer->setAccessTokenExpiry(new DateInterval('PT30S'));
    $oauthServer->setRefreshTokenExpiry(new DateInterval('PT5M'));

    // user authentication MUST take place, here we ignore this for simplicity,
    // and assume the user_id is "foo"
    $userId = 'foo';

    // typically you would handle this with your framework or HTTP framework...
    switch ($_SERVER['REQUEST_METHOD']) {
        case 'GET':
        case 'HEAD':
            // optional "shortcut" to avoid "Approval" dialog if the client has
            // the flag "require_approval" set to false
            if ($authorizeResponse = $oauthServer->getAuthorizeResponse($_GET, $userId)) {
                $authorizeResponse->send();
                break;
            }

            // this is an authorization request, parse all parameters and
            // return an array with data that you can use to ask the user
            // for authorization, this is a very minimal HTML form example
            $authorizeVariables = $oauthServer->getAuthorize($_GET);
            $httpResponse = new Response(
                sprintf('<html><head><title>Authorize</title></head><body><pre>%s</pre><form method="post"><button type="submit" name="approve" value="yes">Approve</button><button type="submit" name="approve" value="no">Reject</button></form></body></html>', var_export($authorizeVariables, true)),
                ['Content-Type' => 'text/html']
            );
            // the Response object is a simple HTTP wrapper that has the
            // statusCode, responseHeaders and responseBody, here we send it
            // directly, if you use a framework you can extract those and pass
            // them along...
            $httpResponse->send();
            break;
        case 'POST':
            // you MUST implement CSRF protection!
            $httpResponse = $oauthServer->postAuthorize($_GET, $_POST, $userId);
            $httpResponse->send();
            break;
        default:
            // typically your HTTP framework would take care of this, but here
            // in "plain" PHP we have to take care of it...
            $httpResponse = new Response('[405] Method Not Allowed', ['Content-Type' => 'text/html', 'Allow' => 'GET,HEAD,POST'], 405);
            $httpResponse->send();
    }
} catch (OAuthException $e) {
    $httpResponse = new Response(
        sprintf('[%s] %s (%s)', $e->getCode(), $e->getMessage(), $e->getDescription()),
        ['Content-Type' => 'text/html'],
        400
    );
    $httpResponse->send();
} catch (Exception $e) {
    // typically your HTTP framework would take care of this, but here
    // in "plain" PHP we have to take care of it... here we catch all
    // "internal server" errors
    $httpResponse = new Response(
        sprintf('[500] %s', $e->getMessage()),
        ['Content-Type' => 'text/html'],
        500
    );
    $httpResponse->send();
}
