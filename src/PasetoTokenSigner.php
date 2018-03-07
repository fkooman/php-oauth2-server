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

namespace fkooman\OAuth\Server;

use DateTime;
use ParagonIE\Paseto\Builder;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\Parser;
use ParagonIE\Paseto\Protocol\Version2;
use ParagonIE\Paseto\ProtocolCollection;
use ParagonIE\Paseto\Purpose;

class PasetoTokenSigner implements TokenSignerInterface
{
    /** @var \ParagonIE\Paseto\Keys\AsymmetricSecretKey */
    private $secretKey;

    public function __construct(AsymmetricSecretKey $secretKey)
    {
        $this->secretKey = $secretKey;
    }

    /**
     * @param array     $listOfClaims
     * @param \DateTime $expiresAt
     *
     * @return string
     */
    public function sign(array $listOfClaims, DateTime $expiresAt)
    {
        return (new Builder())
            ->setKey($this->secretKey)
            ->setVersion(new Version2())
            ->setPurpose(Purpose::public())
            ->setExpiration($expiresAt)
            ->setClaims($listOfClaims)
            ->toString();
    }

    /**
     * @param string $providedToken
     *
     * @return array
     */
    public function parse($providedToken)
    {
        $parser = Parser::getPublic(
            $this->secretKey->getPublicKey(),
            ProtocolCollection::v2()
        );

        try {
            $token = $parser->parse($providedToken);

            return $token->getClaims();
        } catch (PasetoException $ex) {
            // XXX actually do something useful here, sync with other impls
            // THROW something?
            return [];
        }
    }
}
