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

$baseDir = \dirname(__DIR__);
/** @psalm-suppress UnresolvableInclude */
require_once \sprintf('%s/vendor/autoload.php', $baseDir);

use fkooman\OAuth\Server\BearerValidator;
use fkooman\OAuth\Server\ClientInfo;
use fkooman\OAuth\Server\Exception\OAuthException;
use fkooman\OAuth\Server\Http\JsonResponse;
use fkooman\OAuth\Server\SodiumSigner;
use fkooman\OAuth\Server\Storage;

try {
    // persistent storage for access_token authorizations
    $storage = new Storage(new PDO(\sprintf('sqlite:%s/data/db.sqlite', $baseDir)));
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
        if (!\array_key_exists($clientId, $oauthClients)) {
            return false;
        }

        return new ClientInfo($oauthClients[$clientId]);
    };

    $bearerValidator = new BearerValidator(
        $storage,
        $getClientInfo,
        new SodiumSigner(
            // see README on how to generate a "server.key"
            \file_get_contents('server.key')
        )
    );

    switch ($_SERVER['REQUEST_METHOD']) {
        case 'GET':
        case 'HEAD':
            // get the "Authorization" header from the HTTP request
            $authorizationHeader = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : null;

            // obtain tokenInfo from the "Authorization", this contains the
            // user_id the authorization is bound to, as well as some other
            // information, e.g. approved "scope"
            $tokenInfo = $bearerValidator->validate($authorizationHeader);

            // require both the "foo" and "bar" scope
            $tokenInfo->requireAllScope(['foo', 'bar']);
            // require any of "foo" or "bar" scope
            //$tokenInfo->requireAnyScope(['foo', 'bar']);

            // use "helper" JsonResponse here, typically your HTTP framework
            // will provide this...
            $jsonResponse = new JsonResponse(
                ['user_id' => $tokenInfo->getUserId()]
            );
            $jsonResponse->send();
            break;
        default:
            // typically your HTTP framework would take care of this, but here
            // in "plain" PHP we have to take care of it...
            $jsonResponse = new JsonResponse(
                ['error' => 'invalid_request', 'error_description' => 'Method Not Allowed'],
                ['Allow' => 'GET,HEAD'],
                405
            );
            $jsonResponse->send();
    }
} catch (OAuthException $e) {
    // the Exception contains an JsonResponse
    \error_log(\var_export($e->getJsonResponse(), true));
    $e->getJsonResponse()->send();
} catch (Exception $e) {
    // typically your HTTP framework would take care of this, but here
    // in "plain" PHP we have to take care of it... here we catch all
    // "internal server" errors
    $jsonResponse = new JsonResponse(
        ['error' => 'server_error', 'error_description' => $e->getMessage()],
        [],
        500
    );
    $jsonResponse->send();
}
