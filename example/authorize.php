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
use fkooman\OAuth\Server\Http\HtmlResponse;
use fkooman\OAuth\Server\OAuthServer;
use fkooman\OAuth\Server\Storage;

try {
    // persistent storage for access_token authorizations
    $storage = new Storage(new PDO(sprintf('sqlite:%s/data/db.sqlite', dirname(__DIR__))));
    $storage->init();

    // callback to "convert" a client_id into a ClientInfo object, typically
    // this configuration comes from a configuration file or database...
    $getClientInfo = function ($clientId) {
        $oauthClients = [
            // we only have one client here with client_id "demo_client"...
            'demo_client' => [
                'redirect_uri' => ['http://localhost:8081/callback.php'],
                'display_name' => 'Demo Client',
                'client_secret' => 'demo_secret',
            ],
        ];

        // if the client with this client_id does not exist, we return false...
        if (!array_key_exists($clientId, $oauthClients)) {
            return false;
        }

        return new ClientInfo($oauthClients[$clientId]);
    };

    // the 3rd argument is a generated keypair, see README
    $oauthServer = new OAuthServer(
        $storage,
        $getClientInfo,
        '2y5vJlGqpjTzwr3Ym3UqNwJuI1BKeLs53fc6Zf84kbYcP2/6Ar7zgiPS6BL4bvCaWN4uatYfuP7Dj/QvdctqJRw/b/oCvvOCI9LoEvhu8JpY3i5q1h+4/sOP9C91y2ol'
    );

    // we expire issued access_tokens after 30 seconds, the default is 3600
    // seconds (1 hour)
    $oauthServer->setExpiresIn(30);

    // user authentication MUST take place, here we ignore this for simplicity,
    // and assume the user_id is "foo"
    $userId = 'foo';

    // typically you would handle this with your framework or HTTP framework...
    switch ($_SERVER['REQUEST_METHOD']) {
        case 'GET':
        case 'HEAD':
            // this is an authorization request, parse all parameters and
            // return an array with data that you can use to ask the user
            // for authorization, this is a very minimal HTML form example
            $authorizeVariables = $oauthServer->getAuthorize($_GET);
            $htmlResponse = new HtmlResponse(
                sprintf('<html><head><title>Authorize</title></head><body><pre>%s</pre><form method="post"><button type="submit" name="approve" value="yes">Approve</button><button type="submit" name="approve" value="no">Reject</button></form></body></html>', var_export($authorizeVariables, true))
            );
            // the HtmlResponse is a simple HTTP wrapper that has the
            // statusCode, responseHeaders and responseBody, here we send it
            // directly, if you use a framework you can extract those and pass
            // them along...
            $htmlResponse->send();
            break;
        case 'POST':
            // you MUST implement CSRF protection!
            $htmlResponse = $oauthServer->postAuthorize($_GET, $_POST, $userId);
            $htmlResponse->send();
            break;
        default:
            // typically your HTTP framework would take care of this, but here
            // in "plain" PHP we have to take care of it...
            $htmlResponse = new HtmlResponse('[405] Method Not Allowed', ['Allow' => 'GET,HEAD,POST'], 405);
            $htmlResponse->send();
    }
} catch (OAuthException $e) {
    $htmlResponse = new HtmlResponse(
        sprintf('[%s] %s (%s)', $e->getCode(), $e->getMessage(), $e->getDescription()),
        [],
        400
    );
    $htmlResponse->send();
} catch (Exception $e) {
    // typically your HTTP framework would take care of this, but here
    // in "plain" PHP we have to take care of it... here we catch all
    // "internal server" errors
    $htmlResponse = new HtmlResponse(
        sprintf('[500] %s', $e->getMessage()),
        [],
        500
    );
    $htmlResponse->send();
}
