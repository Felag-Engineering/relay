-- template_set_fingerprint is the node-self-reported fingerprint of the Node's
-- loaded Template Operation set (ADR-0021), refreshed on each Hello Upsert
-- beside policy_fingerprint. Report-only: templates are locally rooted and the
-- Relay can never set them (ADR-0002) — this column exists so a template
-- rollout is confirmable fleet-wide exactly like a Policy rollout.
-- Additive: pre-existing rows default to '' ("no templates reported").
ALTER TABLE nodes ADD COLUMN template_set_fingerprint TEXT NOT NULL DEFAULT '';
