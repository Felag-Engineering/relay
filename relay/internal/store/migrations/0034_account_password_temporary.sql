-- A temporary password for a Console human (ADR-0045).
--
-- temporary_until '' is a password the human (or `relay init`) set. An
-- RFC3339Nano UTC instant is a temporary password: it is refused at and after
-- that instant, and a change by the human replaces it with a row holding ''.
-- Every existing row was set by `relay init`, so '' is correct for it.
ALTER TABLE account_passwords ADD COLUMN temporary_until TEXT NOT NULL DEFAULT '';
