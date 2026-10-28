-- AP-88: an elicited approval answer records how the Relay identified its
-- decider: an OAuth session, an API Token session, or a responder assertion.
--
-- Nullable with no default: an out-of-band decision, and every row written
-- before this migration, has no identification to record, and NULL is the
-- honest representation of that. Otherwise the column holds the string form of
-- approval.IdentifiedBy.
ALTER TABLE approval_decisions ADD COLUMN identified_by TEXT;
