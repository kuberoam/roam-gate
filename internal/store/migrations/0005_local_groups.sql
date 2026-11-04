-- Gate's own groups (identity.LocalGroupRoles): developer, techlead, admin
-- and cluster-admin. Putting a user in one grants the role it maps to at
-- once, through the Binding seeded below for each — no binding to create
-- by hand per person.
CREATE TABLE local_group_members (
  group_name TEXT NOT NULL,
  user_id    TEXT NOT NULL,
  added_by   TEXT NOT NULL DEFAULT '',
  added      INTEGER NOT NULL,
  PRIMARY KEY (group_name, user_id)
);

INSERT INTO bindings (id, subject_kind, subject, role, scope, namespaces, note, created_by, created) VALUES
  ('group-developer',     'group', 'roam-gate:developer',     'roam-gate-developer', 'cluster', '[]', 'Gate''s own group — add members under People', 'roam-gate', strftime('%s', 'now') * 1000),
  ('group-techlead',      'group', 'roam-gate:techlead',      'roam-gate-techlead',  'cluster', '[]', 'Gate''s own group — add members under People', 'roam-gate', strftime('%s', 'now') * 1000),
  ('group-admin',         'group', 'roam-gate:admin',         'admin',               'cluster', '[]', 'Gate''s own group — add members under People', 'roam-gate', strftime('%s', 'now') * 1000),
  ('group-cluster-admin', 'group', 'roam-gate:cluster-admin', 'cluster-admin',       'cluster', '[]', 'Gate''s own group — add members under People', 'roam-gate', strftime('%s', 'now') * 1000);
