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

use fkooman\OAuth\Server\ClientInfo;

/**
 * @param string $clientId
 *
 * @return false|\fkooman\OAuth\Server\ClientInfo
 */
function getClientInfo($clientId)
{
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
}
