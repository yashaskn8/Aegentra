-- Run only in a disposable migrated database as the fixture owner, with the
-- backend CI app role and grants. Set -v row_cursor=false for the old query.
\set ON_ERROR_STOP on
BEGIN;
\set org 10000000-0000-0000-0000-000000000001
\set asset 10000000-0000-0000-0000-000000000002
\set actor 10000000-0000-0000-0000-000000000003
\set cid 10000000-0000-0000-0000-000000000004
INSERT INTO organizations(id, slug) VALUES (:'org', 'page-bench');
INSERT INTO assets(org_id, id, slug, criticality) VALUES (:'org', :'asset', 'page-bench', 'LOW');
INSERT INTO identities(org_id, id, issuer, subject, role, active, membership_version)
VALUES (:'org', :'actor', 'https://fixture.example.test/', 'page-bench', 'ANALYST', true, 1);
INSERT INTO investigation_cases(org_id, id, asset_id, title, created_by, status, revision, created_at)
VALUES (:'org', :'cid', :'asset', 'Synthetic page benchmark', :'actor', 'OPEN', 1, '2026-01-01');
INSERT INTO case_memberships(org_id, case_id, identity_id, grant_type) VALUES (:'org', :'cid', :'actor', 'OWNER');
INSERT INTO evidence(org_id, id, asset_id, digest, kind)
SELECT :'org'::uuid, lpad(to_hex(i), 32, '0')::uuid, :'asset'::uuid, decode(repeat('ab', 32), 'hex'), 'synthetic'
FROM generate_series(1, 100000) AS g(i);
INSERT INTO case_evidence(org_id, asset_id, case_id, evidence_id, linked_by, linked_at)
SELECT :'org'::uuid, :'asset'::uuid, :'cid'::uuid, lpad(to_hex(i), 32, '0')::uuid, :'actor'::uuid,
       timestamptz '2026-01-01 00:00:00+00' + ((i - 1)/4) * interval '1 second'
FROM generate_series(1, 100000) AS g(i);
ANALYZE evidence;
ANALYZE case_evidence;

SET LOCAL ROLE aegentra_app;
SELECT set_config('aegentra.org_id', :'org', true);
\if :row_cursor
  \set cursor '(c.linked_at, c.evidence_id) > (timestamptz ''2026-01-01 06:15:00+00'', lpad(to_hex(90002), 32, ''0'')::uuid)'
\else
  \set cursor '(c.linked_at > timestamptz ''2026-01-01 06:15:00+00'' OR (c.linked_at = timestamptz ''2026-01-01 06:15:00+00'' AND c.evidence_id > lpad(to_hex(90002), 32, ''0'')::uuid))'
\endif
EXPLAIN (ANALYZE, BUFFERS, TIMING OFF)
SELECT e.org_id, e.id, e.asset_id, e.digest, e.kind,
       c.org_id, c.asset_id, c.case_id, c.evidence_id, c.linked_by, c.linked_at
FROM evidence AS e JOIN case_evidence AS c
  ON c.org_id=e.org_id AND c.asset_id=e.asset_id AND c.evidence_id=e.id
WHERE c.org_id=:'org'::uuid AND c.asset_id=:'asset'::uuid AND c.case_id=:'cid'::uuid
  AND :cursor
ORDER BY c.linked_at, c.evidence_id LIMIT 26;
\g
\g
\g
\g
\g
ROLLBACK;
