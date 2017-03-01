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
use PDOException;

class Storage
{
    /** @var \PDO */
    private $db;

    public function __construct(PDO $db)
    {
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        if ('sqlite' === $db->getAttribute(PDO::ATTR_DRIVER_NAME)) {
            $db->query('PRAGMA foreign_keys = ON');
        }

        $this->db = $db;
    }

    public function logAuthKey($authKey, DateTime $dateTime)
    {
        // we will attempt to store the authKey in the database, there is a
        // duplicate contraint, so it will fail if the identical authKey is
        // already there
        //
        // we will also store the datetime, so we can cleanup the table
        //
        try {
            $stmt = $this->db->prepare(
                'INSERT INTO auth_key_log (
                    auth_key,
                    date_time
                 ) 
                 VALUES(
                    :auth_key,
                    :date_time
                 )'
            );

            $stmt->bindValue(':auth_key', $authKey, PDO::PARAM_STR);
            $stmt->bindValue(':date_time', $dateTime->format('Y-m-d H:i:s'), PDO::PARAM_STR);
            $stmt->execute();

            return true;
        } catch (PDOException $e) {
            // insert failed, so this is a replay of the authorization code
            return false;
        }
    }

    public function hasAuthorization($authKey)
    {
        $stmt = $this->db->prepare(
            'SELECT
                COUNT(*)
             FROM authorizations
             WHERE
                auth_key = :auth_key'
        );

        $stmt->bindValue(':auth_key', $authKey, PDO::PARAM_STR);
        $stmt->execute();

        return 1 === (int) $stmt->fetchColumn(0);
    }

    public function storeAuthorization($userId, $clientId, $scope, $authKey)
    {
        $stmt = $this->db->prepare(
            'INSERT INTO authorizations (
                auth_key,
                user_id,
                client_id,
                scope
             ) 
             VALUES(
                :auth_key,
                :user_id, 
                :client_id,
                :scope
             )'
        );

        $stmt->bindValue(':auth_key', $authKey, PDO::PARAM_STR);
        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->bindValue(':client_id', $clientId, PDO::PARAM_STR);
        $stmt->bindValue(':scope', $scope, PDO::PARAM_STR);
        $stmt->execute();
    }

    public function getAuthorizations($userId)
    {
        $stmt = $this->db->prepare(
            'SELECT
                auth_key,
                client_id,
                scope
             FROM authorizations
             WHERE
                user_id = :user_id
             GROUP BY client_id, scope'
        );

        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function deleteAuthorization($authKey)
    {
        $stmt = $this->db->prepare(
            'DELETE FROM
                authorizations
             WHERE
                auth_key = :auth_key'
        );

        $stmt->bindValue(':auth_key', $authKey, PDO::PARAM_STR);
        $stmt->execute();

        // XXX we could also remove the entry from the auth_key_log here
        // as reuse of the code has no impact anymore
    }

    public function init()
    {
        $queryList = [
            'CREATE TABLE IF NOT EXISTS authorizations (
                auth_key VARCHAR(255) NOT NULL,
                user_id VARCHAR(255) NOT NULL,
                client_id VARCHAR(255) NOT NULL,
                scope VARCHAR(255) NOT NULL,
                UNIQUE(auth_key)
            )',
            'CREATE TABLE IF NOT EXISTS auth_key_log (
                auth_key VARCHAR(255) NOT NULL,
                date_time VARCHAR(255) NOT NULL,
                UNIQUE(auth_key)
            )',
        ];

        foreach ($queryList as $query) {
            $this->db->query($query);
        }
    }
}
