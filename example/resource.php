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

use fkooman\OAuth\Server\BearerLocalValidator;
use fkooman\OAuth\Server\Exception\BearerException;
use fkooman\OAuth\Server\Storage;

try {
    $storage = new Storage(new PDO(sprintf('sqlite:%s/data/db.sqlite', dirname(__DIR__))));
    $storage->init();

    $bearerValidator = new BearerLocalValidator(
        '2y5vJlGqpjTzwr3Ym3UqNwJuI1BKeLs53fc6Zf84kbYcP2/6Ar7zgiPS6BL4bvCaWN4uatYfuP7Dj/QvdctqJRw/b/oCvvOCI9LoEvhu8JpY3i5q1h+4/sOP9C91y2ol',
        $storage
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
