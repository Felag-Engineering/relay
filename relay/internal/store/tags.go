package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

var _ audit.TagWriteAppender = (*sqliteAudit)(nil)

// AppendWithTagWrite applies changes to tag_labels and chains rs onto the trail
// in one transaction: on a nil error every change and every record landed, on a
// non-nil error none did. rs[i] records changes[i].
//
// This is the only function that writes tag_labels. The changes are written
// before the records, so a record that cannot be written rolls every change
// back. Each change's Before is re-checked against the RAW stored row inside
// the transaction (registry.ErrTagChanged), which is also how a row declined on
// read-back is kept from ever being rewritten or deleted through the filtered
// view. A Node that gains a tag is counted afterwards against
// registry.MaxTagsPerNode (registry.ErrTooManyTags). Every malformed call is
// refused before BeginTx.
func (a *sqliteAudit) AppendWithTagWrite(ctx context.Context, rs []audit.Record, changes []registry.TagChange) error {
	if len(changes) == 0 {
		return errors.New("store: refusing a tag write with no changes")
	}
	if len(rs) != len(changes) {
		return errors.New("store: a tag write needs exactly one audit record per change")
	}
	type nodeKey struct{ nodeID, key string }
	seen := make(map[nodeKey]struct{}, len(changes))
	for i, c := range changes {
		switch {
		case rs[i].ID == "":
			return errors.New("store: refusing to record a tag write with no audit record id")
		case rs[i].Kind != audit.KindTagWrite:
			return errors.New("store: a tag write is recorded only as a tag_write record")
		case rs[i].NodeID != c.NodeID:
			return errors.New("store: a tag write record must name the Node its change names")
		}
		if err := c.Validate(); err != nil {
			return fmt.Errorf("store: refusing a malformed tag change: %w", err)
		}
		k := nodeKey{c.NodeID, c.Key}
		if _, dup := seen[k]; dup {
			return errors.New("store: refusing a tag write that changes one tag twice")
		}
		seen[k] = struct{}{}
	}
	prepared := make([]preparedAudit, len(rs))
	for i, r := range rs {
		p, err := prepareAudit(r)
		if err != nil {
			return err
		}
		prepared[i] = p
	}

	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tag write: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	grew := map[string]struct{}{}
	for _, c := range changes {
		exists, err := nodeExists(ctx, tx, c.NodeID)
		if err != nil {
			return err
		}
		if !exists {
			return registry.ErrNotFound
		}

		var stored string
		err = tx.QueryRowContext(ctx, `SELECT value FROM tag_labels WHERE node_id = ? AND key = ?`, c.NodeID, c.Key).Scan(&stored)
		present := err == nil
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("read tag: %w", err)
		}
		if present != c.Before.Set || (present && stored != c.Before.Value) {
			return registry.ErrTagChanged
		}

		if c.After.Set {
			if !present {
				grew[c.NodeID] = struct{}{}
			}
			_, err = tx.ExecContext(ctx, `
				INSERT INTO tag_labels (node_id, key, value) VALUES (?, ?, ?)
				ON CONFLICT(node_id, key) DO UPDATE SET value = excluded.value`,
				c.NodeID, c.Key, c.After.Value)
		} else {
			_, err = tx.ExecContext(ctx, `DELETE FROM tag_labels WHERE node_id = ? AND key = ?`, c.NodeID, c.Key)
		}
		if err != nil {
			return fmt.Errorf("write tag: %w", err)
		}
	}

	// Only a Node that gained a tag is held to the cap, so a Node already over
	// it can still shed one.
	for nodeID := range grew {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM tag_labels WHERE node_id = ?`, nodeID).Scan(&n); err != nil {
			return fmt.Errorf("count tags: %w", err)
		}
		if n > registry.MaxTagsPerNode {
			return registry.ErrTooManyTags
		}
	}

	if err := insertChained(ctx, tx, prepared); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tag write and records: %w", err)
	}
	return nil
}
