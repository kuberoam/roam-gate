-- App sign-in returns to the app's loopback address with a one-time code;
-- the token is only handed over to whoever holds both the poll secret and
-- that code.
ALTER TABLE login_requests ADD COLUMN return_url TEXT NOT NULL DEFAULT '';
ALTER TABLE login_requests ADD COLUMN code_hash TEXT NOT NULL DEFAULT '';
CREATE INDEX sessions_provider ON sessions (provider);
