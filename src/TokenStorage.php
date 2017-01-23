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

class TokenStorage
{
    /** @var \PDO */
    private $tokenDb;

    public function __construct(PDO $tokenDb)
    {
        $tokenDb->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        if ('sqlite' === $tokenDb->getAttribute(PDO::ATTR_DRIVER_NAME)) {
            $tokenDb->query('PRAGMA foreign_keys = ON');
        }

        $this->tokenDb = $tokenDb;
    }

    public function storeCode($userId, $authorizationCodeKey, $authorizationCode, $clientId, $scope, $redirectUri, DateTime $dateTime, $codeChallenge)
    {
        $stmt = $this->tokenDb->prepare(
            'INSERT INTO codes (
                user_id,    
                authorization_code_key,
                authorization_code,
                client_id,
                scope,
                redirect_uri,
                issued_at,
                code_challenge
             ) 
             VALUES(
                :user_id, 
                :authorization_code_key,
                :authorization_code,
                :client_id,
                :scope,
                :redirect_uri,
                :issued_at,
                :code_challenge
             )'
        );

        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->bindValue(':authorization_code_key', $authorizationCodeKey, PDO::PARAM_STR);
        $stmt->bindValue(':authorization_code', $authorizationCode, PDO::PARAM_STR);
        $stmt->bindValue(':client_id', $clientId, PDO::PARAM_STR);
        $stmt->bindValue(':scope', $scope, PDO::PARAM_STR);
        $stmt->bindValue(':redirect_uri', $redirectUri, PDO::PARAM_STR);
        $stmt->bindValue(':issued_at', $dateTime->format('Y-m-d H:i:s'), PDO::PARAM_STR);
        $stmt->bindValue(':code_challenge', $codeChallenge, PDO::PARAM_STR);
        $stmt->execute();
    }

    public function storeToken($userId, $accessTokenKey, $accessToken, $clientId, $scope, DateTime $expiresAt)
    {
        $stmt = $this->tokenDb->prepare(
            'INSERT INTO tokens (
                user_id,    
                access_token_key,
                access_token,
                client_id,
                scope,
                expires_at
             ) 
             VALUES(
                :user_id, 
                :access_token_key,
                :access_token,
                :client_id,
                :scope,
                :expires_at
             )'
        );

        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->bindValue(':access_token_key', $accessTokenKey, PDO::PARAM_STR);
        $stmt->bindValue(':access_token', $accessToken, PDO::PARAM_STR);
        $stmt->bindValue(':client_id', $clientId, PDO::PARAM_STR);
        $stmt->bindValue(':scope', $scope, PDO::PARAM_STR);
        $stmt->bindValue(':expires_at', $expiresAt->format('Y-m-d H:i:s'), PDO::PARAM_STR);

        $stmt->execute();
    }

    public function getToken($accessTokenKey)
    {
        $stmt = $this->tokenDb->prepare(
            'SELECT
                user_id,    
                access_token,
                client_id,
                scope,
                expires_at
             FROM tokens
             WHERE
                access_token_key = :access_token_key'
        );

        $stmt->bindValue(':access_token_key', $accessTokenKey, PDO::PARAM_STR);
        $stmt->execute();

        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function getCode($authorizationCodeKey)
    {
        $stmt = $this->tokenDb->prepare(
            'SELECT
                user_id,    
                authorization_code_key,
                authorization_code,
                client_id,
                scope,
                redirect_uri,
                issued_at,
                code_challenge
             FROM codes
             WHERE
                authorization_code_key = :authorization_code_key'
        );

        $stmt->bindValue(':authorization_code_key', $authorizationCodeKey, PDO::PARAM_STR);
        $stmt->execute();

        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function getAuthorizedClients($userId)
    {
        $stmt = $this->tokenDb->prepare(
            'SELECT
                client_id,
                scope
             FROM tokens
             WHERE
                user_id = :user_id
             GROUP BY client_id, scope'
        );

        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function removeClientTokens($userId, $clientId)
    {
        // delete authorization_code(s)
        $stmt = $this->tokenDb->prepare(
            'DELETE FROM codes
             WHERE user_id = :user_id AND client_id = :client_id'
        );

        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->bindValue(':client_id', $clientId, PDO::PARAM_STR);
        $stmt->execute();

        // delete access_token(s)
        $stmt = $this->tokenDb->prepare(
            'DELETE FROM tokens
             WHERE user_id = :user_id AND client_id = :client_id'
        );

        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->bindValue(':client_id', $clientId, PDO::PARAM_STR);
        $stmt->execute();
    }

    public function init()
    {
        $queryList = [
            'CREATE TABLE IF NOT EXISTS tokens (
                user_id VARCHAR(255) NOT NULL,
                access_token_key VARCHAR(255) NOT NULL,
                access_token VARCHAR(255) NOT NULL,
                client_id VARCHAR(255) NOT NULL,
                scope VARCHAR(255) NOT NULL,
                expires_at VARCHAR(255) NOT NULL,
                UNIQUE(access_token_key)
            )',
            'CREATE TABLE IF NOT EXISTS codes (
                user_id VARCHAR(255) NOT NULL,
                authorization_code_key VARCHAR(255) NOT NULL,
                authorization_code VARCHAR(255) NOT NULL,
                client_id VARCHAR(255) NOT NULL,
                scope VARCHAR(255) NOT NULL,
                redirect_uri VARCHAR(255) NOT NULL,
                issued_at VARCHAR(255) NOT NULL,
                code_challenge VARCHAR(255) NOT NULL,
                UNIQUE(authorization_code_key)
            )',
        ];

        foreach ($queryList as $query) {
            $this->tokenDb->query($query);
        }
    }
}
