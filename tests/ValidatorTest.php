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

    /**
     * @expectedException \fkooman\OAuth\Server\Exception\OAuthException
     * @expectedExceptionMessage: invalid_token
     */
    public function testNoAuth()
    {
        $validator = new Validator($this->tokenStorage, new DateTime('2016-01-01'));
        $validator->validate(null);
    }

    /**
     * @expectedException \fkooman\OAuth\Server\Exception\OAuthException
     * @expectedExceptionMessage: invalid_token
     */
    public function testInvalidAccessTokenKey()
    {
        $validator = new Validator($this->tokenStorage, new DateTime('2016-01-01'));
        $validator->validate('Bearer aaaa.abcdefgh');
    }

    /**
     * @expectedException \fkooman\OAuth\Server\Exception\OAuthException
     * @expectedExceptionMessage: invalid_token
     */
    public function testInvalidAccessToken()
    {
        $validator = new Validator($this->tokenStorage, new DateTime('2016-01-01'));
        $validator->validate('Bearer 1234.aaaaaaaa');
    }

    /**
     * @expectedException \fkooman\OAuth\Server\Exception\OAuthException
     * @expectedExceptionMessage: invalid_token
     */
    public function testInvalidSyntax()
    {
        $validator = new Validator($this->tokenStorage, new DateTime('2016-01-01'));
        $validator->validate('Bearer %%%%');
    }

    /**
     * @expectedException \fkooman\OAuth\Server\Exception\OAuthException
     * @expectedExceptionMessage: invalid_token
     */
    public function testExpiredToken()
    {
        $validator = new Validator($this->tokenStorage, new DateTime('2017-01-01'));
        $validator->validate('Bearer 1234.abcdefgh');
    }

    /**
     * @expectedException \fkooman\OAuth\Server\Exception\OAuthException
     * @expectedExceptionMessage: invalid_token
     */
    public function testNoDot()
    {
        $validator = new Validator($this->tokenStorage, new DateTime('2016-01-01'));
        $validator->validate('Bearer abcdef');
    }

    /**
     * @expectedException \fkooman\OAuth\Server\Exception\OAuthException
     * @expectedExceptionMessage: invalid_token
     */
    public function testBasicAuthentication()
    {
        $validator = new Validator($this->tokenStorage, new DateTime('2016-01-01'));
        $validator->validate('Basic AAA===');
    }
}
