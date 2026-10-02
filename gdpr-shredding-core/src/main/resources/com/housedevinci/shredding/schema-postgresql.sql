-- GDPR Shredding schema (PostgreSQL). Idempotent, and serialised against the erasure store's
-- appends and against other instances starting at the same time: the whole script runs in one
-- transaction under the store's advisory lock (see JdbcSupport.initializeSchema).
SELECT pg_catalog.pg_advisory_xact_lock(6072873668427846209);

-- Keyed-from-birth, module B's decision carried over (control 8): shredding_erasure.key_id and
-- shredding_erasure_anchor.keyed are NOT NULL in the CREATE TABLE bodies below, with no backfill.
-- This branch is unreleased, so there is no upgrade path from a database written by an earlier
-- build. A pre-redesign table is refused here with a clear message rather than left to fail later
-- on a trigger or a missing column.
-- Both oids are resolved against quote_ident(current_schema()) explicitly, because to_regclass
-- resolves like a reference (the first schema on the search_path that holds the name) while an
-- unqualified CREATE TABLE targets current_schema() only. Module B, security-review findings
-- J1 and K1.
-- Every catalogue name below carries its pg_catalog. prefix (finding C-13-12). A function name
-- resolves along search_path exactly as a relation name does, and on the initialize-schema=true
-- path this script runs with the application's own credentials - a role that may ALTER ROLE
-- <itself> SET search_path and that owns a schema it can define functions in. An app.to_regclass()
-- returning NULL makes the guard below unable to RAISE at all, and in the same move takes the
-- tgrelid scoping out of all five trigger guards (CIPHER-05) below.
DO $$
DECLARE
  e oid := pg_catalog.to_regclass(
    pg_catalog.quote_ident(pg_catalog.current_schema()) || '.shredding_erasure');
  n oid := pg_catalog.to_regclass(
    pg_catalog.quote_ident(pg_catalog.current_schema()) || '.shredding_erasure_anchor');
BEGIN
  IF (e IS NOT NULL
      AND NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_attribute
        WHERE attrelid = e AND attname = 'key_id' AND attnum > 0 AND NOT attisdropped))
     OR (n IS NOT NULL
      AND NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_attribute
        WHERE attrelid = n AND attname = 'keyed' AND attnum > 0 AND NOT attisdropped)) THEN
    RAISE EXCEPTION
      'erasure log predates keyed-from-birth; archive the table and start a new trail (see SECURITY-NOTES)';
  END IF;
END $$;

-- Per-(tenant, subject, version) data keys. The tenant is part of the primary key (control 15):
-- the same subject id under two tenants is two subjects, two keys and two erasures.
-- wrapped_key holds nonce || ciphertext || tag, sealed under the master key with
-- AAD tenant|subject|version, so a row cannot be swapped between subjects (control 5).
CREATE TABLE IF NOT EXISTS shredding_data_key (
  tenant           varchar(255) NOT NULL,
  subject          varchar(255) NOT NULL,
  version          integer      NOT NULL,
  wrapped_key      bytea        NOT NULL,
  state            varchar(16)  NOT NULL,
  encryption_count bigint       NOT NULL DEFAULT 0,
  created_at       timestamptz  NOT NULL,
  PRIMARY KEY (tenant, subject, version)
);
CREATE INDEX IF NOT EXISTS shredding_data_key_subject
  ON shredding_data_key (tenant, subject);

-- Erased subjects. The key rows are deleted outright; this table is the record that the subject
-- was erased, so no later write can mint a fresh key for it and quietly undo the erasure
-- (control 11). It holds no key material at all, which is what separates it from the
-- "overwrite then delete" theatre control 6 rejects.
CREATE TABLE IF NOT EXISTS shredding_erased_subject (
  tenant    varchar(255) NOT NULL,
  subject   varchar(255) NOT NULL,
  erased_at timestamptz  NOT NULL,
  PRIMARY KEY (tenant, subject)
);

-- The erasure log: the proof that a key was destroyed, and the one table that must outlive the
-- data it is about. The subject appears only as a keyed pseudonym (control 9).
CREATE TABLE IF NOT EXISTS shredding_erasure (
  seq                 bigserial PRIMARY KEY,
  ts                  timestamptz  NOT NULL,
  tenant              varchar(255) NOT NULL,
  subject_pseudonym   char(64)     NOT NULL,
  requested_by        varchar(1000) NOT NULL DEFAULT '',
  reason              varchar(1000) NOT NULL DEFAULT '',
  keys_destroyed      integer      NOT NULL DEFAULT 0,
  entity_count        integer      NOT NULL DEFAULT 0,
  field_count         integer      NOT NULL DEFAULT 0,
  blind_index_cleared integer      NOT NULL DEFAULT 0,
  outcome             varchar(16)  NOT NULL,
  hook_outcomes       text         NOT NULL DEFAULT '',
  backup_clear_at     timestamptz  NOT NULL,
  chain_version       varchar(8)   NOT NULL,
  key_id              varchar(64)  NOT NULL,
  prev_hash           char(64)     NOT NULL,
  hash                char(64)     NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS shredding_erasure_subject
  ON shredding_erasure (tenant, subject_pseudonym, ts);

-- Append-only: UPDATE, DELETE and TRUNCATE are refused at the database level. A role that owns the
-- table can still DISABLE TRIGGER, so run the application with a role that has INSERT/SELECT only;
-- the anchor below makes tail deletion and truncation detectable even then.
--
-- CIPHER-05: pg_trigger is database-wide and trigger names are per-table, so a bare tgname check
-- with no tgrelid predicate is satisfied by the same-named trigger on a *different* schema's copy
-- of this table; every guard below resolves tgrelid against quote_ident(current_schema()) the same
-- way the keyed-from-birth check above does, so a second schema is not silently left unguarded.
CREATE OR REPLACE FUNCTION shredding_erasure_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% is append-only (attempted %)', TG_TABLE_NAME, TG_OP;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;
DO $$ BEGIN
  IF NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_trigger
      WHERE tgname = 'shredding_erasure_append_only'
        AND tgrelid = pg_catalog.to_regclass(
          pg_catalog.quote_ident(pg_catalog.current_schema()) || '.shredding_erasure')) THEN
    CREATE TRIGGER shredding_erasure_append_only
      BEFORE UPDATE OR DELETE ON shredding_erasure
      FOR EACH ROW EXECUTE FUNCTION shredding_erasure_append_only();
  END IF;
END $$;
DO $$ BEGIN
  IF NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_trigger
      WHERE tgname = 'shredding_erasure_no_truncate'
        AND tgrelid = pg_catalog.to_regclass(
          pg_catalog.quote_ident(pg_catalog.current_schema()) || '.shredding_erasure')) THEN
    CREATE TRIGGER shredding_erasure_no_truncate
      BEFORE TRUNCATE ON shredding_erasure
      FOR EACH STATEMENT EXECUTE FUNCTION shredding_erasure_append_only();
  END IF;
END $$;

-- Append-only, the same as shredding_erasure and for the same reason (CIPHER-04): the runtime role
-- needs INSERT on this table so mint() and erase() can write the tombstone, and the same grant
-- that allows INSERT allows DELETE unless the trigger refuses it. Deleting the tombstone lets
-- mint() mint again for a subject the erasure log says is erased, which is exactly as dangerous as
-- deleting an erasure row, so it gets the same two triggers, defined only once the function above
-- exists to point them at.
DO $$ BEGIN
  IF NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_trigger
      WHERE tgname = 'shredding_erased_subject_append_only'
        AND tgrelid = pg_catalog.to_regclass(
          pg_catalog.quote_ident(pg_catalog.current_schema()) || '.shredding_erased_subject')) THEN
    CREATE TRIGGER shredding_erased_subject_append_only
      BEFORE UPDATE OR DELETE ON shredding_erased_subject
      FOR EACH ROW EXECUTE FUNCTION shredding_erasure_append_only();
  END IF;
END $$;
DO $$ BEGIN
  IF NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_trigger
      WHERE tgname = 'shredding_erased_subject_no_truncate'
        AND tgrelid = pg_catalog.to_regclass(
          pg_catalog.quote_ident(pg_catalog.current_schema()) || '.shredding_erased_subject')) THEN
    CREATE TRIGGER shredding_erased_subject_no_truncate
      BEFORE TRUNCATE ON shredding_erased_subject
      FOR EACH STATEMENT EXECUTE FUNCTION shredding_erasure_append_only();
  END IF;
END $$;

-- Chain anchor: head hash + row count + the trail's keyed/unkeyed mode, written in the same
-- transaction as every append. `keyed` is set once, at the first append, and is immutable
-- afterwards: it is the external, attacker-unwritable record of what every row's chain_version
-- ought to be, because that column is itself part of what a table-owning attacker rewrites.
CREATE TABLE IF NOT EXISTS shredding_erasure_anchor (
  id         smallint PRIMARY KEY CHECK (id = 1),
  head_hash  char(64) NOT NULL,
  row_count  bigint NOT NULL,
  updated_at timestamptz NOT NULL,
  keyed      boolean NOT NULL
);

CREATE OR REPLACE FUNCTION shredding_erasure_anchor_monotonic() RETURNS trigger AS $$
BEGIN
  -- `keyed` is checked first: a caller that also gets the row count wrong must still be told the
  -- real problem, which is that it is trying to change the trail's mode.
  -- Every operator is written OPERATOR(pg_catalog....) and every binary application of one is
  -- parenthesised. Both halves are load-bearing (C-13-14). Qualified, because this body is not
  -- SECURITY DEFINER and - absent this function's own SET search_path clause - resolves its
  -- operator names in the session of whoever writes to the anchor; a role that owns one schema
  -- may define its own =(boolean,boolean), <>(bigint,bigint) and =(bpchar,bpchar).
  -- Parenthesised, because every OPERATOR(...)-qualified operator takes one generic
  -- precedence, so an unparenthesised
  -- `a OPERATOR(pg_catalog.<>) b OPERATOR(pg_catalog.+) 1` parses as `(a <> b) + 1` and raises
  -- `operator does not exist: boolean pg_catalog.+ integer` at run time, on the honest append.
  -- IS DISTINCT FROM cannot be operator-qualified at all, so `keyed` is compared with <>; the
  -- column is NOT NULL on both OLD and NEW, so the two are equivalent here.
  IF NEW.keyed OPERATOR(pg_catalog.<>) OLD.keyed THEN
    RAISE EXCEPTION 'shredding_erasure_anchor.keyed is immutable once set (attempted % -> %)',
      OLD.keyed, NEW.keyed;
  END IF;
  IF (NEW.row_count OPERATOR(pg_catalog.<>) (OLD.row_count OPERATOR(pg_catalog.+) 1))
     OR (NEW.head_hash OPERATOR(pg_catalog.=) OLD.head_hash) THEN
    RAISE EXCEPTION 'shredding_erasure_anchor only advances by one row (attempted % -> %)',
      OLD.row_count, NEW.row_count;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;
DO $$ BEGIN
  IF NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_trigger
      WHERE tgname = 'shredding_erasure_anchor_monotonic'
        AND tgrelid = pg_catalog.to_regclass(
          pg_catalog.quote_ident(pg_catalog.current_schema()) || '.shredding_erasure_anchor')) THEN
    CREATE TRIGGER shredding_erasure_anchor_monotonic
      BEFORE UPDATE ON shredding_erasure_anchor
      FOR EACH ROW EXECUTE FUNCTION shredding_erasure_anchor_monotonic();
  END IF;
END $$;

CREATE OR REPLACE FUNCTION shredding_erasure_anchor_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% is append-only (attempted %)', TG_TABLE_NAME, TG_OP;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;
DO $$ BEGIN
  IF NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_trigger
      WHERE tgname = 'shredding_erasure_anchor_no_delete'
        AND tgrelid = pg_catalog.to_regclass(
          pg_catalog.quote_ident(pg_catalog.current_schema()) || '.shredding_erasure_anchor')) THEN
    CREATE TRIGGER shredding_erasure_anchor_no_delete
      BEFORE DELETE ON shredding_erasure_anchor
      FOR EACH ROW EXECUTE FUNCTION shredding_erasure_anchor_append_only();
  END IF;
END $$;
DO $$ BEGIN
  IF NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_trigger
      WHERE tgname = 'shredding_erasure_anchor_no_truncate'
        AND tgrelid = pg_catalog.to_regclass(
          pg_catalog.quote_ident(pg_catalog.current_schema()) || '.shredding_erasure_anchor')) THEN
    CREATE TRIGGER shredding_erasure_anchor_no_truncate
      BEFORE TRUNCATE ON shredding_erasure_anchor
      FOR EACH STATEMENT EXECUTE FUNCTION shredding_erasure_anchor_append_only();
  END IF;
END $$;

-- C-12-1, design section 4.4: the seven guards are set to ENABLE ALWAYS, unconditionally and
-- idempotently, every time this script runs. Two reasons, and neither is cosmetic.
--   1. A trigger created by CREATE TRIGGER is `O` (origin): it does not fire for a replication
--      apply worker, for a superuser session in `session_replication_role = replica`, or under
--      `pg_restore --disable-triggers`. `A` (always) fires in all three. It does NOT defend
--      against the table's owner, who needs none of that: ALTER TABLE ... DISABLE TRIGGER is
--      already theirs. Say which actor, not "it protects the log".
--   2. Before this, the script had no way to repair a trigger someone had disabled - the
--      CREATE TRIGGER blocks above are all guarded by "IF NOT EXISTS", so a disabled trigger
--      stayed disabled through every re-apply. Re-applying the script is now the documented and
--      the working remedy for tgenabled = 'D', 'R' or 'O' (docs/upgrading-0.2.0.md step 3).
-- Startup verification refuses anything other than 'A', so these seven statements are what makes
-- that refusal payable rather than a wall an operator cannot climb.
ALTER TABLE shredding_erasure        ENABLE ALWAYS TRIGGER shredding_erasure_append_only;
ALTER TABLE shredding_erasure        ENABLE ALWAYS TRIGGER shredding_erasure_no_truncate;
ALTER TABLE shredding_erased_subject ENABLE ALWAYS TRIGGER shredding_erased_subject_append_only;
ALTER TABLE shredding_erased_subject ENABLE ALWAYS TRIGGER shredding_erased_subject_no_truncate;
ALTER TABLE shredding_erasure_anchor ENABLE ALWAYS TRIGGER shredding_erasure_anchor_monotonic;
ALTER TABLE shredding_erasure_anchor ENABLE ALWAYS TRIGGER shredding_erasure_anchor_no_delete;
ALTER TABLE shredding_erasure_anchor ENABLE ALWAYS TRIGGER shredding_erasure_anchor_no_truncate;

-- The schema step never seeds an anchor row from an existing, non-empty trail: deriving `keyed`
-- from row data is exactly the guess the anchor exists to make unnecessary. A trail with rows and
-- no anchor is refused at startup and on every append (SHRED-ERASURE-002); the operator remedy is
-- to archive the pair and start a new trail. For an empty trail there is nothing to seed: the
-- first real append creates the anchor row.
