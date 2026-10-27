-- A mutate Job that stops sending after its first failure records why on its
-- own row (execution.md, Halting a failing mutation): the halting Task, its
-- Node and outcome, whether that outcome is the Task's recorded resolution, and
-- when. It is written once, by the Job engine.
--
-- NO BACKFILL. NULL halt_task_id means "never halted", which covers every
-- pre-existing row. halt_resolved is meaningful only when halt_task_id is set.
ALTER TABLE jobs ADD COLUMN halt_task_id TEXT;
ALTER TABLE jobs ADD COLUMN halt_node_id TEXT;
ALTER TABLE jobs ADD COLUMN halt_outcome INTEGER;
ALTER TABLE jobs ADD COLUMN halt_resolved INTEGER NOT NULL DEFAULT 0;
ALTER TABLE jobs ADD COLUMN halted_at TEXT;
