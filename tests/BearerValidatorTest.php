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

class BearerValidatorTest extends PHPUnit_Framework_TestCase
{
    /** @var Storage */
    private $storage;

    /** @var array */
    private $publicKey;

    public function setUp()
    {
        $this->storage = new Storage(new PDO('sqlite::memory:'));
        $this->storage->init();

        $this->publicKey = [
            base64_decode('HD9v+gK+84Ij0ugS+G7wmljeLmrWH7j+w4/0L3XLaiU='),
            base64_decode('Nls2Vq7y+Edv0ympv2juM2qij2XUlOaM7eaC+4pxgzw='),
        ];
    }

    public function testValidToken()
    {
        $validator = new BearerValidator($this->storage, $this->publicKey[0], new DateTime('2016-01-01'));
        $this->assertSame(
            [
                'user_id' => 'foo',
                'scope' => 'config',
                'expires_in' => 3600,
            ],
            $validator->validate('Bearer pr/mlAkRzsPXb5X1h3UEeNpLfqFyD550vGrwYc7kuGD01sWJ84DDy4JdlWlFHR4a7dBXPAkS/BPi8Yuc26PqCXsidHlwZSI6ImFjY2Vzc190b2tlbiIsImtleSI6InJhbmRvbV8xIiwidXNlcl9pZCI6ImZvbyIsImNsaWVudF9pZCI6ImNvZGUtY2xpZW50Iiwic2NvcGUiOiJjb25maWciLCJleHBpcmVzX2F0IjoiMjAxNi0wMS0wMSAwMTowMDowMCJ9')
        );
    }

    public function testNoAuth()
    {
        $validator = new BearerValidator($this->storage, $this->publicKey[0], new DateTime('2016-01-01'));
        $this->assertFalse($validator->validate(null));
    }

    /**
     * @expectedException \fkooman\OAuth\Server\Exception\BearerException
     * @expectedExceptionMessage: invalid_token
     */
    public function testInvalidSyntax()
    {
        $validator = new BearerValidator($this->storage, $this->publicKey[0], new DateTime('2016-01-01'));
        $validator->validate('Bearer %%%%');
    }

    /**
     * @expectedException \fkooman\OAuth\Server\Exception\BearerException
     * @expectedExceptionMessage: invalid_token
     */
    public function testExpiredToken()
    {
        $validator = new BearerValidator($this->storage, $this->publicKey[0], new DateTime('2017-01-01'));
        $validator->validate('Bearer pr/mlAkRzsPXb5X1h3UEeNpLfqFyD550vGrwYc7kuGD01sWJ84DDy4JdlWlFHR4a7dBXPAkS/BPi8Yuc26PqCXsidHlwZSI6ImFjY2Vzc190b2tlbiIsImtleSI6InJhbmRvbV8xIiwidXNlcl9pZCI6ImZvbyIsImNsaWVudF9pZCI6ImNvZGUtY2xpZW50Iiwic2NvcGUiOiJjb25maWciLCJleHBpcmVzX2F0IjoiMjAxNi0wMS0wMSAwMTowMDowMCJ9');
    }

    /**
     * @expectedException \fkooman\OAuth\Server\Exception\BearerException
     * @expectedExceptionMessage: invalid_token
     */
    public function testInvalidSignatureKey()
    {
        $validator = new BearerValidator($this->storage, $this->publicKey[1], new DateTime('2016-01-01'));
        $validator->validate('Bearer pr/mlAkRzsPXb5X1h3UEeNpLfqFyD550vGrwYc7kuGD01sWJ84DDy4JdlWlFHR4a7dBXPAkS/BPi8Yuc26PqCXsidHlwZSI6ImFjY2Vzc190b2tlbiIsImtleSI6InJhbmRvbV8xIiwidXNlcl9pZCI6ImZvbyIsImNsaWVudF9pZCI6ImNvZGUtY2xpZW50Iiwic2NvcGUiOiJjb25maWciLCJleHBpcmVzX2F0IjoiMjAxNi0wMS0wMSAwMTowMDowMCJ9');
    }

    public function testBasicAuthentication()
    {
        $validator = new BearerValidator($this->storage, $this->publicKey[0], new DateTime('2016-01-01'));
        $this->assertFalse($validator->validate('Basic AAA==='));
    }
}
