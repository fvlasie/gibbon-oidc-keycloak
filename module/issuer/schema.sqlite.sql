CREATE TABLE IF NOT EXISTS oidcRealm (
  oidcRealmID INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  issuerUrl TEXT NOT NULL,
  accessTtl INTEGER NOT NULL DEFAULT 300,
  idTtl INTEGER NOT NULL DEFAULT 300,
  refreshTtl INTEGER NOT NULL DEFAULT 2592000,
  activeKeyKid TEXT
);

CREATE TABLE IF NOT EXISTS oidcSigningKey (
  kid TEXT PRIMARY KEY,
  publicJwk TEXT NOT NULL,
  privatePem TEXT NOT NULL,
  active TEXT NOT NULL DEFAULT 'Y',
  created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS oidcClient (
  oidcClientID INTEGER PRIMARY KEY AUTOINCREMENT,
  clientId TEXT NOT NULL UNIQUE,
  clientSecretHash TEXT,
  public TEXT NOT NULL DEFAULT 'Y',
  redirectUris TEXT NOT NULL,
  postLogoutUris TEXT,
  allowedScopes TEXT NOT NULL DEFAULT 'openid profile email offline_access roles',
  pkceRequired TEXT NOT NULL DEFAULT 'Y',
  allowedOrigins TEXT
);

CREATE TABLE IF NOT EXISTS oidcClaimMap (
  oidcClaimMapID INTEGER PRIMARY KEY AUTOINCREMENT,
  gibbonRoleID INTEGER NOT NULL,
  realmRole TEXT NOT NULL,
  opencloudRole TEXT,
  clientId TEXT,
  clientRole TEXT
);

CREATE TABLE IF NOT EXISTS oidcAuthCode (
  codeHash TEXT PRIMARY KEY,
  gibbonPersonID INTEGER NOT NULL,
  clientId TEXT NOT NULL,
  redirectUri TEXT NOT NULL,
  scope TEXT NOT NULL,
  nonce TEXT,
  codeChallenge TEXT,
  codeChallengeMethod TEXT,
  sessionId TEXT NOT NULL,
  expires INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oidcRefreshToken (
  tokenHash TEXT PRIMARY KEY,
  gibbonPersonID INTEGER NOT NULL,
  clientId TEXT NOT NULL,
  scope TEXT NOT NULL,
  sessionId TEXT NOT NULL,
  expires INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oidcSession (
  sessionId TEXT PRIMARY KEY,
  gibbonPersonID INTEGER NOT NULL,
  expires INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS gibbonRole (
  gibbonRoleID INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'Other'
);

CREATE TABLE IF NOT EXISTS gibbonPerson (
  gibbonPersonID INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  passwordStrong TEXT NOT NULL,
  email TEXT,
  firstName TEXT,
  surname TEXT,
  officialName TEXT,
  status TEXT NOT NULL DEFAULT 'Full',
  gibbonRoleIDPrimary INTEGER,
  gibbonRoleIDAll TEXT
);
