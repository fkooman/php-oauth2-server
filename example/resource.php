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
use fkooman\OAuth\Server\Storage;

try {
    $storage = new Storage(new PDO(sprintf('sqlite:%s/data/db.sqlite', dirname(__DIR__))));
    $storage->init();

    $bearerValidator = new BearerValidator(
        $storage,
        '2y5vJlGqpjTzwr3Ym3UqNwJuI1BKeLs53fc6Zf84kbYcP2/6Ar7zgiPS6BL4bvCaWN4uatYfuP7Dj/QvdctqJRw/b/oCvvOCI9LoEvhu8JpY3i5q1h+4/sOP9C91y2ol'
    );

    switch ($_SERVER['REQUEST_METHOD']) {
        case 'GET':
            $authorizationHeader = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : null;
            $tokenInfo = $bearerValidator->validate($authorizationHeader);
            http_response_code(200);
            header('Content-Type: application/json');
            echo json_encode(
                ['user_id' => $tokenInfo['user_id']]
            );
            break;
        default:
            http_response_code(405);
            header('Content-Type: application/json');
            header('Allow: GET');
            echo json_encode(['error' => 'invalid_request', 'error_description' => 'Method Not Allowed']);
    }
} catch (BearerException $e) {
    http_response_code($e->getCode());
    header('Content-Type: application/json');
    if (401 === $e->getCode()) {
        header(sprintf('WWW-Authenticate: Bearer error="%s"', $e->getMessage()));
    }
    echo json_encode(['error' => $e->getMessage(), 'error_description' => $e->getDescription()]);
} catch (Exception $e) {
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'server_error', 'error_description' => $e->getMessage()]);
}
