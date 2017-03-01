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
use PHPUnit_Framework_TestCase;

class BearerValidatorTest extends PHPUnit_Framework_TestCase
{
    /** @var array */
    private $publicKeys;

    public function setUp()
    {
        $this->publicKeys = [
            'HD9v+gK+84Ij0ugS+G7wmljeLmrWH7j+w4/0L3XLaiU=',
            'caA2Uepr6fv+3xx/R26ig6ceQic+gFHGIMJNoXy8m8U=',
        ];
    }

    public function testValidToken()
    {
        $validator = new BearerValidator($this->publicKeys, new DateTime('2016-01-01'));
        $this->assertSame(
            [
                'user_id' => 'foo',
                'scope' => 'config',
                'expires_in' => 3600,
            ],
            $validator->validate('Bearer znwcwk0WpP1y0qrUSd/J6KToSlXdceGBaliVLhYYjRESQoVZI1aZTX9cRfBfIpOBnMcyTF3Izs9H8918OwiqBHsidHlwZSI6ImFjY2Vzc190b2tlbiIsImF1dGhfa2V5IjoicmFuZG9tXzEiLCJ1c2VyX2lkIjoiZm9vIiwiY2xpZW50X2lkIjoiY29kZS1jbGllbnQiLCJzY29wZSI6ImNvbmZpZyIsImV4cGlyZXNfYXQiOiIyMDE2LTAxLTAxIDAxOjAwOjAwIn0=')
        );
    }

    /**
     * @expectedException \fkooman\OAuth\Server\Exception\BearerException
     * @expectedExceptionMessage: invalid_token
     */
    public function testNoAuth()
    {
        $validator = new BearerValidator($this->publicKeys, new DateTime('2016-01-01'));
        $validator->validate(null);
    }

    /**
     * @expectedException \fkooman\OAuth\Server\Exception\BearerException
     * @expectedExceptionMessage: invalid_token
     */
    public function testInvalidSyntax()
    {
        $validator = new BearerValidator($this->publicKeys, new DateTime('2016-01-01'));
        $validator->validate('Bearer %%%%');
    }

    /**
     * @expectedException \fkooman\OAuth\Server\Exception\BearerException
     * @expectedExceptionMessage: invalid_token
     */
    public function testExpiredToken()
    {
        $validator = new BearerValidator($this->publicKeys, new DateTime('2017-01-01'));
        $validator->validate('Bearer pr/mlAkRzsPXb5X1h3UEeNpLfqFyD550vGrwYc7kuGD01sWJ84DDy4JdlWlFHR4a7dBXPAkS/BPi8Yuc26PqCXsidHlwZSI6ImFjY2Vzc190b2tlbiIsImtleSI6InJhbmRvbV8xIiwidXNlcl9pZCI6ImZvbyIsImNsaWVudF9pZCI6ImNvZGUtY2xpZW50Iiwic2NvcGUiOiJjb25maWciLCJleHBpcmVzX2F0IjoiMjAxNi0wMS0wMSAwMTowMDowMCJ9');
    }

    /**
     * @expectedException \fkooman\OAuth\Server\Exception\BearerException
     * @expectedExceptionMessage: invalid_token
     */
    public function testInvalidSignatureKey()
    {
        $validator = new BearerValidator([$this->publicKeys[1]], new DateTime('2016-01-01'));
        $validator->validate('Bearer pr/mlAkRzsPXb5X1h3UEeNpLfqFyD550vGrwYc7kuGD01sWJ84DDy4JdlWlFHR4a7dBXPAkS/BPi8Yuc26PqCXsidHlwZSI6ImFjY2Vzc190b2tlbiIsImtleSI6InJhbmRvbV8xIiwidXNlcl9pZCI6ImZvbyIsImNsaWVudF9pZCI6ImNvZGUtY2xpZW50Iiwic2NvcGUiOiJjb25maWciLCJleHBpcmVzX2F0IjoiMjAxNi0wMS0wMSAwMTowMDowMCJ9');
    }

    /**
     * @expectedException \fkooman\OAuth\Server\Exception\BearerException
     * @expectedExceptionMessage: invalid_token
     */
    public function testBasicAuthentication()
    {
        $validator = new BearerValidator($this->publicKeys, new DateTime('2016-01-01'));
        $this->assertFalse($validator->validate('Basic AAA==='));
    }
}
