-- Audit filters the admin screen uses that 0001 didn't index: without these,
-- "denied only" and a kind filter walk the table back from the newest event
-- until they fill a page (seconds on tens of millions of rows).
CREATE INDEX audit_denied ON audit (id) WHERE allowed = 0;
CREATE INDEX audit_kind ON audit (kind, id);
CREATE INDEX audit_resource ON audit (resource, verb, id);
