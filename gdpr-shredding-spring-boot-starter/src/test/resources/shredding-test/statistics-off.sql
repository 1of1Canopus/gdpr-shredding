-- TEST FIXTURE ONLY, never shipped: applied by Testcontainers as the superuser when a test
-- container starts (withInitScript). Since 0.2.0 a blind-index column must keep no planner
-- statistics (SHRED-SCHEMA-010, docs/upgrading-0.2.0.md step 3a), and Hibernate's ddl-auto cannot
-- emit SET STATISTICS. This event trigger applies the documented first statement,
-- SET STATISTICS 0, to every column of every table a test creates or alters, as that table's
-- owner, before any row exists, so a fixture schema starts the way an operator's schema ends
-- step 3a. The statistics tests (PlannerStatistics*Test, the starter's boot test) do not install
-- it: they are the ones that must see a default target refused. A same-named copy lives in the
-- core and starter test resources.
CREATE SCHEMA shredding_test;
CREATE FUNCTION shredding_test.statistics_off() RETURNS event_trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT DISTINCT n.nspname, c.relname, a.attname
      FROM pg_catalog.pg_event_trigger_ddl_commands() e
      JOIN pg_catalog.pg_class c ON c.oid = e.objid
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
     WHERE e.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
       AND c.relkind IN ('r', 'p')
       AND a.attnum > 0 AND NOT a.attisdropped AND a.attgenerated <> 'v'
       AND a.attstattarget IS DISTINCT FROM 0
       AND pg_catalog.pg_has_role(c.relowner, 'USAGE')
  LOOP
    EXECUTE pg_catalog.format('ALTER TABLE %I.%I ALTER COLUMN %I SET STATISTICS 0',
                              r.nspname, r.relname, r.attname);
  END LOOP;
END
$fn$;
CREATE EVENT TRIGGER shredding_test_statistics_off ON ddl_command_end
  WHEN TAG IN ('CREATE TABLE', 'ALTER TABLE', 'CREATE TABLE AS', 'SELECT INTO')
  EXECUTE FUNCTION shredding_test.statistics_off();
