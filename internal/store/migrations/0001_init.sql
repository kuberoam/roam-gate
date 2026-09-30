CREATE TABLE providers (
  id      TEXT PRIMARY KEY,
  type    TEXT NOT NULL,
  name    TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  config  BLOB NOT NULL,          -- AES-GCM sealed JSON (secrets included)
  created INTEGER NOT NULL,
  updated INTEGER NOT NULL
);

CREATE TABLE users (
  id         TEXT PRIMARY KEY,
  provider   TEXT NOT NULL,
  name       TEXT NOT NULL DEFAULT '',
  email      TEXT NOT NULL DEFAULT '',
  groups     TEXT NOT NULL DEFAULT '[]',
  first_seen INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL,
  disabled   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE sessions (
  id         TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,  -- SHA-256 of the token; the token itself is never stored
  user       TEXT NOT NULL,
  groups     TEXT NOT NULL DEFAULT '[]',
  provider   TEXT NOT NULL,
  created    INTEGER NOT NULL,
  expires    INTEGER NOT NULL,
  last_used  INTEGER NOT NULL,
  ip         TEXT NOT NULL DEFAULT '',
  ua         TEXT NOT NULL DEFAULT '',
  revoked    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX sessions_user ON sessions (user);

CREATE TABLE login_requests (
  id        TEXT PRIMARY KEY,
  poll_hash TEXT NOT NULL,
  created   INTEGER NOT NULL,
  expires   INTEGER NOT NULL,
  state     TEXT NOT NULL,
  token     BLOB,                   -- sealed; deleted once collected
  error     TEXT NOT NULL DEFAULT ''
);

CREATE TABLE bindings (
  id           TEXT PRIMARY KEY,
  subject_kind TEXT NOT NULL,
  subject      TEXT NOT NULL,
  role         TEXT NOT NULL,
  scope        TEXT NOT NULL,
  namespaces   TEXT NOT NULL DEFAULT '[]',
  note         TEXT NOT NULL DEFAULT '',
  created_by   TEXT NOT NULL DEFAULT '',
  created      INTEGER NOT NULL
);

CREATE TABLE audit (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          INTEGER NOT NULL,       -- unix milliseconds
  kind        TEXT NOT NULL,
  user        TEXT NOT NULL DEFAULT '',
  groups      TEXT NOT NULL DEFAULT '[]',
  session     TEXT NOT NULL DEFAULT '',
  verb        TEXT NOT NULL DEFAULT '',
  resource    TEXT NOT NULL DEFAULT '',
  subresource TEXT NOT NULL DEFAULT '',
  namespace   TEXT NOT NULL DEFAULT '',
  name        TEXT NOT NULL DEFAULT '',
  path        TEXT NOT NULL DEFAULT '',
  status      INTEGER NOT NULL DEFAULT 0,
  allowed     INTEGER NOT NULL DEFAULT 1,
  ip          TEXT NOT NULL DEFAULT '',
  ua          TEXT NOT NULL DEFAULT '',
  duration_ms INTEGER NOT NULL DEFAULT 0,
  detail      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_ts ON audit (ts);
CREATE INDEX audit_user ON audit (user, id);
CREATE INDEX audit_namespace ON audit (namespace, id);
