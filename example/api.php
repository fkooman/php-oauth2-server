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

use fkooman\OAuth\Server\BearerValidator;
use fkooman\OAuth\Server\Exception\BearerException;
use fkooman\OAuth\Server\Http\ApiResponse;
use fkooman\OAuth\Server\Storage;

try {
    // persistent storage for access_token authorizations
    $storage = new Storage(new PDO(sprintf('sqlite:%s/data/db.sqlite', dirname(__DIR__))));
    $storage->init();

    // the 2nd argument is a generated keypair, see README
    $bearerValidator = new BearerValidator(
        $storage,
        '2y5vJlGqpjTzwr3Ym3UqNwJuI1BKeLs53fc6Zf84kbYcP2/6Ar7zgiPS6BL4bvCaWN4uatYfuP7Dj/QvdctqJRw/b/oCvvOCI9LoEvhu8JpY3i5q1h+4/sOP9C91y2ol'
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

            // use "helper" ApiResponse here, typically your HTTP framework
            // will provide this...
            $apiResponse = new ApiResponse(
                ['user_id' => $tokenInfo->getUserId()]
            );
            $apiResponse->send();
            break;
        default:
            // typically your HTTP framework would take care of this, but here
            // in "plain" PHP we have to take care of it...
            $apiResponse = new ApiResponse(
                ['error' => 'invalid_request', 'error_description' => 'Method Not Allowed'],
                ['Allow' => 'GET,HEAD'],
                405
            );
            $apiResponse->send();
    }
} catch (BearerException $e) {
    // the Exception contains an ApiResponse
    $e->getResponse()->send();
} catch (Exception $e) {
    // typically your HTTP framework would take care of this, but here
    // in "plain" PHP we have to take care of it... here we catch all
    // "internal server" errors
    $apiResponse = new ApiResponse(
        ['error' => 'server_error', 'error_description' => $e->getMessage()],
        [],
        500
    );
    $apiResponse->send();
}
