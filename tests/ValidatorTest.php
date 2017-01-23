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

namespace fkooman\OAuth\Server;

use DateTime;
use fkooman\OAuth\Server\Exception\TokenException;
use PDO;
use PHPUnit_Framework_TestCase;

class ValidatorTest extends PHPUnit_Framework_TestCase
{
    /** @var TokenStorage */
    private $tokenStorage;

    public function setUp()
    {
        $this->tokenStorage = new TokenStorage(new PDO('sqlite::memory:'));
        $this->tokenStorage->init();

        $this->tokenStorage->storeToken(
            'foo',
            '1234',
            'abcdefgh',
            'vpn-companion',
            'scope',
            new DateTime('2016-01-01')
        );
    }

    public function testValidToken()
    {
        $validator = new Validator($this->tokenStorage, new DateTime('2016-01-01'));
        $this->assertSame(
            [
                'user_id' => 'foo',
                'scope' => 'scope',
            ],
            $validator->validate('Bearer 1234.abcdefgh')
        );
    }

    public function testNoAuth()
    {
        $validator = new Validator($this->tokenStorage, new DateTime('2016-01-01'));
        $response = $this->error($validator, null);
        $this->assertSame(
            [
                'Content-Type' => 'application/json',
                'Cache-Control' => 'no-store',
                'Pragma' => 'no-cache',
                'WWW-Authenticate' => 'Bearer realm="OAuth"',
            ],
            $response->getHeaders()
        );
        $this->assertSame(401, $response->getStatusCode());
    }

    public function testInvalidAccessTokenKey()
    {
        $validator = new Validator($this->tokenStorage, new DateTime('2016-01-01'));
        $response = $this->error($validator, 'Bearer aaaa.abcdefgh');
        $this->assertSame(
            [
                'Content-Type' => 'application/json',
                'Cache-Control' => 'no-store',
                'Pragma' => 'no-cache',
                'WWW-Authenticate' => 'Bearer realm="OAuth",error=invalid_token,error_description=token key does not exist',
            ],
            $response->getHeaders()
        );
        $this->assertSame(401, $response->getStatusCode());
    }

    /**
     * @expectedException \fkooman\OAuth\Server\Exception\TokenException
     * @expectedExceptionMessage: invalid_token
     */
    public function testInvalidAccessToken()
    {
        $validator = new Validator($this->tokenStorage, new DateTime('2016-01-01'));
        $validator->validate('Bearer 1234.aaaaaaaa');
    }

    /**
     * @expectedException \fkooman\OAuth\Server\Exception\TokenException
     * @expectedExceptionMessage: invalid_token
     */
    public function testInvalidSyntax()
    {
        $validator = new Validator($this->tokenStorage, new DateTime('2016-01-01'));
        $validator->validate('Bearer %%%%');
    }

    /**
     * @expectedException \fkooman\OAuth\Server\Exception\TokenException
     * @expectedExceptionMessage: invalid_token
     */
    public function testExpiredToken()
    {
        $validator = new Validator($this->tokenStorage, new DateTime('2017-01-01'));
        $validator->validate('Bearer 1234.abcdefgh');
    }

    /**
     * @expectedException \fkooman\OAuth\Server\Exception\TokenException
     * @expectedExceptionMessage: invalid_token
     */
    public function testNoDot()
    {
        $validator = new Validator($this->tokenStorage, new DateTime('2016-01-01'));
        $validator->validate('Bearer abcdef');
    }

    /**
     * @expectedException \fkooman\OAuth\Server\Exception\TokenException
     * @expectedExceptionMessage: invalid_token
     */
    public function testBasicAuthentication()
    {
        $validator = new Validator($this->tokenStorage, new DateTime('2016-01-01'));
        $validator->validate('Basic AAA===');
    }

    private function error(Validator $validator, $authorizationHeader)
    {
        try {
            $validator->validate($authorizationHeader);
            $this->assertTrue(false);
        } catch (TokenException $e) {
            return $e->getResponse();
        }
    }
}
