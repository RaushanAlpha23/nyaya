-- Run ONCE in the Supabase SQL editor (as the default postgres user).
-- Before running: replace both CHANGE_ME values with long random passwords.
-- Generate one with: python -c "import secrets; print(secrets.token_urlsafe(24))"
-- Use only letters, digits, - and _ so URLs need no encoding.
-- Reference script: verify each statement against the Supabase docs for your project.

-- 1. Two login roles (matches m1_schema.md)
create role nyaya_migrator login password 'CHANGE_ME_MIGRATOR';
create role nyaya_app      login password 'CHANGE_ME_APP';

-- Supabase's postgres user is not a full superuser, so it must be a member of the
-- role it creates a schema for.
grant nyaya_migrator to postgres;

-- 2. A private schema owned by the migrator. Tables go here, not in "public",
-- so Supabase's auto-generated REST API never exposes them.
create schema if not exists nyaya authorization nyaya_migrator;

-- 3. The API role may use the schema, and gets row-level access to future tables.
grant usage on schema nyaya to nyaya_app;

alter default privileges for role nyaya_migrator in schema nyaya
    grant select, insert, update, delete on tables to nyaya_app;
alter default privileges for role nyaya_migrator in schema nyaya
    grant usage, select on sequences to nyaya_app;

-- 4. Both roles use the nyaya schema by default.
alter role nyaya_migrator set search_path = nyaya;
alter role nyaya_app      set search_path = nyaya;

-- 5. Neither role may create objects in public.
revoke create on schema public from nyaya_migrator, nyaya_app;

-- Later, the audit_log migration will revoke UPDATE, DELETE and TRUNCATE
-- from nyaya_app on that one table.
