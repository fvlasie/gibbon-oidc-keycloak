<?php
// Gibbon module updater: list of [version, SQL]

$count = 0;
$sql = [];

$count++;
$sql[$count][0] = '1.0.00';
$sql[$count][1] = "CREATE TABLE IF NOT EXISTS `oidcRealm` (
  `oidcRealmID` int(10) unsigned zerofill NOT NULL AUTO_INCREMENT,
  `name` varchar(64) NOT NULL,
  `issuerUrl` varchar(255) NOT NULL,
  `accessTtl` int unsigned NOT NULL DEFAULT 300,
  `idTtl` int unsigned NOT NULL DEFAULT 300,
  `refreshTtl` int unsigned NOT NULL DEFAULT 2592000,
  `activeKeyKid` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`oidcRealmID`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8";

$count++;
$sql[$count][0] = '1.0.00';
$sql[$count][1] = "CREATE TABLE IF NOT EXISTS `oidcSigningKey` (
  `kid` varchar(64) NOT NULL,
  `publicJwk` text NOT NULL,
  `privatePem` mediumtext NOT NULL,
  `active` enum('Y','N') NOT NULL DEFAULT 'Y',
  `created` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`kid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8";

$count++;
$sql[$count][0] = '1.0.00';
$sql[$count][1] = "CREATE TABLE IF NOT EXISTS `oidcClient` (
  `oidcClientID` int(10) unsigned zerofill NOT NULL AUTO_INCREMENT,
  `clientId` varchar(128) NOT NULL,
  `clientSecretHash` varchar(255) DEFAULT NULL,
  `public` enum('Y','N') NOT NULL DEFAULT 'Y',
  `redirectUris` text NOT NULL,
  `postLogoutUris` text DEFAULT NULL,
  `allowedScopes` varchar(255) NOT NULL DEFAULT 'openid profile email offline_access roles',
  `pkceRequired` enum('Y','N') NOT NULL DEFAULT 'Y',
  `allowedOrigins` text DEFAULT NULL,
  PRIMARY KEY (`oidcClientID`),
  UNIQUE KEY `clientId` (`clientId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8";

$count++;
$sql[$count][0] = '1.0.00';
$sql[$count][1] = "CREATE TABLE IF NOT EXISTS `oidcClaimMap` (
  `oidcClaimMapID` int(10) unsigned zerofill NOT NULL AUTO_INCREMENT,
  `gibbonRoleID` int(3) unsigned zerofill NOT NULL,
  `realmRole` varchar(128) NOT NULL,
  `rolesClaim` varchar(128) DEFAULT NULL,
  `clientId` varchar(128) DEFAULT NULL,
  `clientRole` varchar(128) DEFAULT NULL,
  PRIMARY KEY (`oidcClaimMapID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8";

$count++;
$sql[$count][0] = '1.0.00';
$sql[$count][1] = "CREATE TABLE IF NOT EXISTS `oidcAuthCode` (
  `codeHash` varchar(64) NOT NULL,
  `gibbonPersonID` int(10) unsigned zerofill NOT NULL,
  `clientId` varchar(128) NOT NULL,
  `redirectUri` varchar(512) NOT NULL,
  `scope` varchar(255) NOT NULL,
  `nonce` varchar(255) DEFAULT NULL,
  `codeChallenge` varchar(128) DEFAULT NULL,
  `codeChallengeMethod` varchar(16) DEFAULT NULL,
  `sessionId` varchar(64) NOT NULL,
  `expires` int unsigned NOT NULL,
  PRIMARY KEY (`codeHash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8";

$count++;
$sql[$count][0] = '1.0.00';
$sql[$count][1] = "CREATE TABLE IF NOT EXISTS `oidcRefreshToken` (
  `tokenHash` varchar(64) NOT NULL,
  `gibbonPersonID` int(10) unsigned zerofill NOT NULL,
  `clientId` varchar(128) NOT NULL,
  `scope` varchar(255) NOT NULL,
  `sessionId` varchar(64) NOT NULL,
  `expires` int unsigned NOT NULL,
  PRIMARY KEY (`tokenHash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8";

$count++;
$sql[$count][0] = '1.0.00';
$sql[$count][1] = "CREATE TABLE IF NOT EXISTS `oidcSession` (
  `sessionId` varchar(64) NOT NULL,
  `gibbonPersonID` int(10) unsigned zerofill NOT NULL,
  `expires` int unsigned NOT NULL,
  PRIMARY KEY (`sessionId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8";

$count++;
$sql[$count][0] = '1.0.01';
$oidcSchema = preg_replace('/^--.*$/m', '', (string) file_get_contents(__DIR__.'/issuer/schema.mysql.sql')) ?? '';
$oidcParts = [];
foreach (preg_split('/;\s*/', $oidcSchema) as $stmt) {
    $stmt = trim($stmt);
    if ($stmt !== '') {
        $oidcParts[] = $stmt;
    }
}
$oidcParts[] = "INSERT IGNORE INTO oidcRealm (name, issuerUrl, accessTtl, idTtl, refreshTtl) VALUES ('gibbon', CONCAT(TRIM(TRAILING '/' FROM COALESCE((SELECT value FROM gibbonSetting WHERE scope='System' AND name='absoluteURL' LIMIT 1), '')), '/realms/gibbon'), 300, 300, 2592000)";
$sql[$count][1] = implode(";end\n", $oidcParts).';end';
