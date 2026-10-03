CREATE TABLE IF NOT EXISTS public.b2_note (id bigserial PRIMARY KEY, owner_id varchar(255) NOT NULL, tenant_id varchar(255) NOT NULL, email bytea, email_idx bytea);
