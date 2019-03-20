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
$baseDir = \dirname(__DIR__);

use fkooman\OAuth\Server\ArrayClientDb;
use fkooman\OAuth\Server\BearerValidator;
use fkooman\OAuth\Server\Exception\OAuthException;
use fkooman\OAuth\Server\Http\JsonResponse;
use fkooman\OAuth\Server\LocalSigner;
use fkooman\OAuth\Server\PdoStorage;
use ParagonIE\ConstantTime\Base64UrlSafe;

try {
    // persistent storage for access_token authorizations
    $storage = new PdoStorage(new PDO(\sprintf('sqlite:%s/data/db.sqlite', $baseDir)));
    $storage->init();

    $bearerValidator = new BearerValidator(
        $storage,
        new ArrayClientDb(include __DIR__.'/client_info.php'),
        new LocalSigner(Base64UrlSafe::decode(\file_get_contents('server.key')))
    );

    switch ($_SERVER['REQUEST_METHOD']) {
        case 'GET':
        case 'HEAD':
            // get the "Authorization" header from the HTTP request
            $authorizationHeader = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : null;

            // obtain accessTokenInfo from the "Authorization", this contains
            // the user_id the authorization is bound to, as well as some other
            // information, e.g. approved "scope"
            $accessTokenInfo = $bearerValidator->validate($authorizationHeader);

            // require both the "foo" and "bar" scope
            $accessTokenInfo->getScope()->requireAll(['foo', 'bar']);
            // require any of "foo" or "bar" scope
            //$accessTokenInfo->requireAnyScope(['foo', 'bar']);

            // use "helper" JsonResponse here, typically your HTTP framework
            // will provide this...
            $jsonResponse = new JsonResponse(
                ['user_id' => $accessTokenInfo->getResourceOwner()->getUserId()]
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
