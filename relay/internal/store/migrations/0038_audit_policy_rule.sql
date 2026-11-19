-- Where the daemon's Policy denied a Task, on the audit row of the dispatch
-- outcome that reports it: the pass of its decide, and the deciding rule's
-- section, index and line (display-only on the Relay).
--
-- NULL means not reported, which is true of every row written before this
-- migration, so there is no back-fill. ADD COLUMN does not fire the append-only
-- UPDATE trigger, and the chain hashes the four columns only on a row that
-- carries them, so no stored hash changes and a trail mixing old and new rows
-- verifies.
ALTER TABLE audit ADD COLUMN policy_pass TEXT;
ALTER TABLE audit ADD COLUMN policy_rule_section TEXT;
ALTER TABLE audit ADD COLUMN policy_rule_index INTEGER;
ALTER TABLE audit ADD COLUMN policy_rule_line INTEGER;
