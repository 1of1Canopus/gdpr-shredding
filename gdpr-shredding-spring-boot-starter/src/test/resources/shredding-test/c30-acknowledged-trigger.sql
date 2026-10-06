CREATE TABLE IF NOT EXISTS public.probe_audit_log (note_id bigint)
CREATE OR REPLACE FUNCTION public.shredding_probe_audit() RETURNS trigger AS $$ BEGIN INSERT INTO probe_audit_log (note_id) VALUES (NEW.id); RETURN NEW; END; $$ LANGUAGE plpgsql
CREATE TRIGGER shredding_probe_audit AFTER UPDATE ON public.owned_note FOR EACH ROW EXECUTE FUNCTION public.shredding_probe_audit()
