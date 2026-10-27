-- An Enrollment Token names initial tags, written as each joining Node's first
-- tags, and records which Account minted it (ADR-0050). The relay: labels an
-- earlier release stamped from a token's scope are copied to tags, never moved.
--
-- The columns are plain SQL below. Everything else is the Go step
-- migrationGoSteps[33] (store/initialtags_migration.go), which runs in THIS
-- transaction after these statements. In order, the step:
--
--   1. Records the minting Account on each token, from created_by.
--   2. Converts the scope of every token a human Account minted into
--      initial_tags.
--   3. Copies each relay: label of a Node that token enrolled, other than
--      relay:node-id, to a tag of the same key and value, as that Account's act
--      with one chained tag_write record per tag.
--   4. Logs each token and Node it could not convert or copy, so a person tags
--      them by hand.
--
-- relay_labels rows are copied and never deleted or rewritten. scope keeps its
-- column and its meaning, the legacy relay: scope, which new tokens leave as an
-- empty array.
--
-- COST: one pass over tokens, relay_labels and tag_labels, plus one audit row
-- per copied tag. The whole migration is one transaction, so a failure rolls
-- back and the Relay refuses to start until it is fixed.
ALTER TABLE tokens ADD COLUMN initial_tags TEXT NOT NULL DEFAULT '[]';
ALTER TABLE tokens ADD COLUMN created_by_account_id TEXT NOT NULL DEFAULT '';
ALTER TABLE tokens ADD COLUMN created_by_human INTEGER NOT NULL DEFAULT 0;
