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

namespace fkooman\OAuth\Server\Tests;

use DateTime;
use fkooman\OAuth\Server\BearerValidator;
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
                'auth_key' => 'random_1',
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
