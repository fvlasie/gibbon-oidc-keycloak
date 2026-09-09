<?php

namespace Gibbon\Module\OIDCServer\Issuer;

use PDO;
use PDOException;

class Store
{
    public function __construct(private PDO $pdo)
    {
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    }

    public static function sqlite(string $path): self
    {
        $dir = dirname($path);
        if (!is_dir($dir)) {
            mkdir($dir, 0770, true);
        }
        $pdo = new PDO('sqlite:'.$path);
        $pdo->exec('PRAGMA foreign_keys = ON');
        $schema = file_get_contents(__DIR__.'/../schema.sqlite.sql');
        $pdo->exec($schema);

        return new self($pdo);
    }

    public static function mysql(string $dsn, string $user, string $password): self
    {
        return new self(new PDO($dsn, $user, $password));
    }

    public function pdo(): PDO
    {
        return $this->pdo;
    }

    public function getRealm(string $name): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM oidcRealm WHERE name = ?');
        $stmt->execute([$name]);
        $row = $stmt->fetch();

        return $row ?: null;
    }

    public function upsertRealm(array $realm): void
    {
        $existing = $this->getRealm($realm['name']);
        if ($existing) {
            $stmt = $this->pdo->prepare('UPDATE oidcRealm SET issuerUrl=?, accessTtl=?, idTtl=?, refreshTtl=?, activeKeyKid=? WHERE name=?');
            $stmt->execute([
                $realm['issuerUrl'],
                $realm['accessTtl'],
                $realm['idTtl'],
                $realm['refreshTtl'],
                $realm['activeKeyKid'],
                $realm['name'],
            ]);
            return;
        }
        $stmt = $this->pdo->prepare('INSERT INTO oidcRealm (name, issuerUrl, accessTtl, idTtl, refreshTtl, activeKeyKid) VALUES (?,?,?,?,?,?)');
        $stmt->execute([
            $realm['name'],
            $realm['issuerUrl'],
            $realm['accessTtl'],
            $realm['idTtl'],
            $realm['refreshTtl'],
            $realm['activeKeyKid'],
        ]);
    }

    public function getActiveKey(): ?array
    {
        $stmt = $this->pdo->query("SELECT * FROM oidcSigningKey WHERE active = 'Y' ORDER BY created DESC LIMIT 1");
        $row = $stmt->fetch();

        return $row ?: null;
    }

    public function getKey(string $kid): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM oidcSigningKey WHERE kid = ?');
        $stmt->execute([$kid]);
        $row = $stmt->fetch();

        return $row ?: null;
    }

    public function saveKey(array $key): void
    {
        $this->pdo->exec("UPDATE oidcSigningKey SET active = 'N'");
        $stmt = $this->pdo->prepare('INSERT INTO oidcSigningKey (kid, publicJwk, privatePem, active) VALUES (?,?,?,?)');
        $stmt->execute([$key['kid'], $key['publicJwk'], $key['privatePem'], 'Y']);
    }

    public function listJwks(): array
    {
        $stmt = $this->pdo->query("SELECT publicJwk FROM oidcSigningKey WHERE active = 'Y'");
        $keys = [];
        foreach ($stmt as $row) {
            $keys[] = json_decode($row['publicJwk'], true);
        }

        return $keys;
    }

    public function getClient(string $clientId): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM oidcClient WHERE clientId = ?');
        $stmt->execute([$clientId]);
        $row = $stmt->fetch();

        return $row ?: null;
    }

    public function listClients(): array
    {
        return $this->pdo->query('SELECT * FROM oidcClient ORDER BY clientId')->fetchAll();
    }

    public function upsertClient(array $client): void
    {
        $existing = $this->getClient($client['clientId']);
        $fields = [
            $client['clientSecretHash'] ?? null,
            $client['public'] ?? 'Y',
            $client['redirectUris'],
            $client['postLogoutUris'] ?? '',
            $client['allowedScopes'] ?? 'openid profile email offline_access roles',
            $client['pkceRequired'] ?? 'Y',
            $client['allowedOrigins'] ?? '',
            $client['clientId'],
        ];
        if ($existing) {
            if (empty($client['clientSecretHash'])) {
                $fields[0] = $existing['clientSecretHash'];
            }
            $stmt = $this->pdo->prepare('UPDATE oidcClient SET clientSecretHash=?, public=?, redirectUris=?, postLogoutUris=?, allowedScopes=?, pkceRequired=?, allowedOrigins=? WHERE clientId=?');
            $stmt->execute($fields);
            return;
        }
        $stmt = $this->pdo->prepare('INSERT INTO oidcClient (clientSecretHash, public, redirectUris, postLogoutUris, allowedScopes, pkceRequired, allowedOrigins, clientId) VALUES (?,?,?,?,?,?,?,?)');
        $stmt->execute($fields);
    }

    public function listClaimMaps(): array
    {
        return $this->pdo->query('SELECT * FROM oidcClaimMap')->fetchAll();
    }

    public function replaceClaimMaps(array $maps): void
    {
        $this->pdo->exec('DELETE FROM oidcClaimMap');
        $stmt = $this->pdo->prepare('INSERT INTO oidcClaimMap (gibbonRoleID, realmRole, rolesClaim, clientId, clientRole) VALUES (?,?,?,?,?)');
        foreach ($maps as $map) {
            $stmt->execute([
                $map['gibbonRoleID'],
                $map['realmRole'],
                $map['rolesClaim'] ?? null,
                $map['clientId'] ?? null,
                $map['clientRole'] ?? null,
            ]);
        }
    }

    public function findUserByUsername(string $username): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM gibbonPerson WHERE username = ?');
        $stmt->execute([$username]);
        $row = $stmt->fetch();

        return $row ?: null;
    }

    public function getUser(int $id): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM gibbonPerson WHERE gibbonPersonID = ?');
        $stmt->execute([$id]);
        $row = $stmt->fetch();

        return $row ?: null;
    }

    public function rolesForUser(array $person): array
    {
        $ids = [];
        if (!empty($person['gibbonRoleIDPrimary'])) {
            $ids[] = (int) $person['gibbonRoleIDPrimary'];
        }
        if (!empty($person['gibbonRoleIDAll'])) {
            foreach (preg_split('/[,\s]+/', (string) $person['gibbonRoleIDAll']) as $part) {
                if ($part !== '') {
                    $ids[] = (int) $part;
                }
            }
        }
        $ids = array_values(array_unique(array_filter($ids)));
        if ($ids === []) {
            return [];
        }
        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $stmt = $this->pdo->prepare("SELECT * FROM gibbonRole WHERE gibbonRoleID IN ($placeholders)");
        $stmt->execute($ids);

        return $stmt->fetchAll();
    }

    public function saveAuthCode(array $row): void
    {
        $stmt = $this->pdo->prepare('INSERT INTO oidcAuthCode (codeHash, gibbonPersonID, clientId, redirectUri, scope, nonce, codeChallenge, codeChallengeMethod, sessionId, expires) VALUES (?,?,?,?,?,?,?,?,?,?)');
        $stmt->execute([
            $row['codeHash'],
            $row['gibbonPersonID'],
            $row['clientId'],
            $row['redirectUri'],
            $row['scope'],
            $row['nonce'] ?? null,
            $row['codeChallenge'] ?? null,
            $row['codeChallengeMethod'] ?? null,
            $row['sessionId'],
            $row['expires'],
        ]);
    }

    public function takeAuthCode(string $codeHash): ?array
    {
        $this->pdo->beginTransaction();
        try {
            $stmt = $this->pdo->prepare('SELECT * FROM oidcAuthCode WHERE codeHash = ?');
            $stmt->execute([$codeHash]);
            $row = $stmt->fetch();
            if ($row) {
                $del = $this->pdo->prepare('DELETE FROM oidcAuthCode WHERE codeHash = ?');
                $del->execute([$codeHash]);
            }
            $this->pdo->commit();
        } catch (PDOException $e) {
            $this->pdo->rollBack();
            throw $e;
        }

        return $row ?: null;
    }

    public function saveRefresh(array $row): void
    {
        $stmt = $this->pdo->prepare('INSERT INTO oidcRefreshToken (tokenHash, gibbonPersonID, clientId, scope, sessionId, expires) VALUES (?,?,?,?,?,?)');
        $stmt->execute([
            $row['tokenHash'],
            $row['gibbonPersonID'],
            $row['clientId'],
            $row['scope'],
            $row['sessionId'],
            $row['expires'],
        ]);
    }

    public function takeRefresh(string $tokenHash): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM oidcRefreshToken WHERE tokenHash = ?');
        $stmt->execute([$tokenHash]);
        $row = $stmt->fetch();
        if ($row) {
            $del = $this->pdo->prepare('DELETE FROM oidcRefreshToken WHERE tokenHash = ?');
            $del->execute([$tokenHash]);
        }

        return $row ?: null;
    }

    public function deleteRefresh(string $tokenHash): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM oidcRefreshToken WHERE tokenHash = ?');
        $stmt->execute([$tokenHash]);
    }

    public function saveSession(string $sessionId, int $personId, int $expires): void
    {
        $stmt = $this->pdo->prepare('INSERT INTO oidcSession (sessionId, gibbonPersonID, expires) VALUES (?,?,?)');
        $stmt->execute([$sessionId, $personId, $expires]);
    }

    public function getSession(string $sessionId): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM oidcSession WHERE sessionId = ? AND expires > ?');
        $stmt->execute([$sessionId, time()]);
        $row = $stmt->fetch();

        return $row ?: null;
    }

    public function deleteSession(string $sessionId): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM oidcSession WHERE sessionId = ?');
        $stmt->execute([$sessionId]);
        $this->pdo->prepare('DELETE FROM oidcRefreshToken WHERE sessionId = ?')->execute([$sessionId]);
        $this->pdo->prepare('DELETE FROM oidcAuthCode WHERE sessionId = ?')->execute([$sessionId]);
    }

    public function seedStandaloneDemo(string $issuerUrl): void
    {
        if ($this->getRealm('gibbon')) {
            return;
        }

        $key = Jwt::generateKey();
        $this->saveKey($key);
        $this->upsertRealm([
            'name' => 'gibbon',
            'issuerUrl' => $issuerUrl,
            'accessTtl' => 300,
            'idTtl' => 300,
            'refreshTtl' => 2592000,
            'activeKeyKid' => $key['kid'],
        ]);

        $origin = preg_replace('#/realms/[^/]+$#', '', $issuerUrl);
        $testRpRedirects = implode("\n", [
            $origin.'/test-rp.html',
            $origin.'/test-rp',
            $issuerUrl.'/test-rp.html',
        ]);
        foreach (['web', 'test-rp'] as $id) {
            $this->upsertClient([
                'clientId' => $id,
                'public' => 'Y',
                'redirectUris' => $testRpRedirects,
                'postLogoutUris' => $origin.'/test-rp.html',
                'allowedOrigins' => '*',
                'pkceRequired' => 'Y',
            ]);
        }

        $this->pdo->exec("INSERT INTO gibbonRole (gibbonRoleID, name, category) VALUES
            (1, 'Administrator', 'Staff'),
            (2, 'Teacher', 'Staff'),
            (3, 'Student', 'Student')");

        $hash = password_hash('changeme', PASSWORD_DEFAULT);
        $stmt = $this->pdo->prepare('INSERT INTO gibbonPerson (gibbonPersonID, username, passwordStrong, email, firstName, surname, officialName, status, gibbonRoleIDPrimary, gibbonRoleIDAll) VALUES (?,?,?,?,?,?,?,?,?,?)');
        $stmt->execute([1, 'admin', $hash, 'admin@school.example', 'Ada', 'Admin', 'Ada Admin', 'Full', 1, '1']);
        $stmt->execute([2, 'teacher', $hash, 'teacher@school.example', 'Tomas', 'Teacher', 'Tomas Teacher', 'Full', 2, '2']);
        $stmt->execute([3, 'student', $hash, 'student@school.example', 'Sam', 'Student', 'Sam Student', 'Full', 3, '3']);
        $stmt->execute([4, 'leftuser', $hash, 'left@school.example', 'Lea', 'Left', 'Lea Left', 'Left', 3, '3']);

        $this->replaceClaimMaps([
            ['gibbonRoleID' => 1, 'realmRole' => 'Administrator', 'rolesClaim' => 'admin', 'clientId' => 'web', 'clientRole' => 'admin'],
            ['gibbonRoleID' => 2, 'realmRole' => 'Teacher', 'rolesClaim' => 'user', 'clientId' => 'web', 'clientRole' => 'user'],
            ['gibbonRoleID' => 3, 'realmRole' => 'Student', 'rolesClaim' => 'guest', 'clientId' => 'web', 'clientRole' => 'guest'],
        ]);
    }
}
