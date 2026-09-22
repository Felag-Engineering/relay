-- #616: the Job row now records its requester -- the verified Account that
-- asked for it -- written in the same INSERT that creates the Job, before
-- any Task exists.
--
-- WHY THE REQUESTER LIVES ON THE JOB ROW. Until now a Job's requester was
-- joined from its audit dispatch row, and that row is written only after
-- disp.run returns -- so a running Job had no recorded owner. Moving the
-- requester onto the row the Job engine already writes first means it is
-- durable before any Task is even Pending, let alone Dispatched.
--
-- VERIFIED LANE ONLY. These columns hold the Principal the Relay itself
-- authenticated, never a caller-asserted on_behalf_of value: nothing here
-- lets a caller claim ownership of a Job over the wire.
--
-- NO BACKFILL. Rows written before this migration are deliberately left
-- alone: their requester columns stay NULL, and NULL means "no requester
-- recorded", never "unknown, infer from audit". execution.md's Cancellation
-- section requires fail closed, never assumed, and the audit trail's
-- dispatch principal is exactly the inference that would violate it.
ALTER TABLE jobs ADD COLUMN requester_account_id TEXT;
ALTER TABLE jobs ADD COLUMN requester_account_name TEXT;
ALTER TABLE jobs ADD COLUMN requester_kind TEXT CHECK (requester_kind IN ('human', 'machine'));

-- Partial index following 0021's account_id convention: most legacy rows are
-- NULL, so indexing only the rows that carry a requester is what the
-- RequesterAccountID filter (now a plain column predicate) actually needs.
CREATE INDEX IF NOT EXISTS idx_jobs_requester_created_at ON jobs (requester_account_id, created_at, job_id) WHERE requester_account_id IS NOT NULL;
