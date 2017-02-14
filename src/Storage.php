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

use PDO;

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

    public function hasKey($key)
    {
        $stmt = $this->db->prepare(
            'SELECT
                COUNT(*)
             FROM keys
             WHERE
                key = :key'
        );

        $stmt->bindValue(':key', $key, PDO::PARAM_STR);
        $stmt->execute();

        return 1 === $stmt->fetchColumn(0);
    }

    public function storeKey($userId, $clientId, $scope, $key)
    {
        $stmt = $this->db->prepare(
            'INSERT INTO keys (
                user_id,    
                client_id,
                scope,
                key
             ) 
             VALUES(
                :user_id, 
                :client_id,
                :scope,
                :key
             )'
        );

        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->bindValue(':client_id', $clientId, PDO::PARAM_STR);
        $stmt->bindValue(':scope', $scope, PDO::PARAM_STR);
        $stmt->bindValue(':key', $key, PDO::PARAM_STR);

        $stmt->execute();
    }

    public function getAuthorizedClients($userId)
    {
        $stmt = $this->db->prepare(
            'SELECT
                client_id,
                scope
             FROM keys
             WHERE
                user_id = :user_id
             GROUP BY client_id, scope'
        );

        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function deleteKey($userId, $clientId)
    {
        // delete keys(s)
        $stmt = $this->db->prepare(
            'DELETE FROM keys
             WHERE user_id = :user_id AND client_id = :client_id'
        );

        $stmt->bindValue(':user_id', $userId, PDO::PARAM_STR);
        $stmt->bindValue(':client_id', $clientId, PDO::PARAM_STR);
        $stmt->execute();
    }

    public function init()
    {
        $queryList = [
            'CREATE TABLE IF NOT EXISTS keys (
                user_id VARCHAR(255) NOT NULL,
                client_id VARCHAR(255) NOT NULL,
                scope VARCHAR(255) NOT NULL,
                key VARCHAR(255) NOT NULL,
                UNIQUE(key)
            )',
        ];

        foreach ($queryList as $query) {
            $this->db->query($query);
        }
    }
}
