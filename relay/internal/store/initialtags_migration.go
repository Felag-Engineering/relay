package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// Migration 33's Go step: an unused Enrollment Token's relay: scope becomes initial
// tags, and the relay: labels it stamped on Nodes are copied to tags (ADR-0050
// decision 3). It is Go because the copy appends chained audit rows.
//
// COUPLING: the audit rows go through insertChained, which writes the LIVE audit
// column set. A later migration that adds an audit column must keep this step
// runnable on a database still at version 32, for example by giving the column a
// default and keeping insertChained's write compatible.
// TestMigration0033_ScopeLabelsBecomeTagsAndTheAuditChainVerifies is the
// tripwire.

// Why a label was not copied to a tag. These are the reasons logged, and the
// runbook names them.
const (
	reasonMachineMinted  = "minted_by_machine_or_unknown_account"
	reasonDeclined       = "declined"
	reasonTagExists      = "tag_exists"
	reasonTagLimit       = "tag_limit"
	reasonNodeIDMismatch = "node_id_mismatch"
)

// A relay:node-id label is never copied. It is skipped silently when it names the
// Node it is on, and listed as reasonNodeIDMismatch when it names another.

// tokenMinter is the Account a token's created_by names, as the accounts table
// knows it. A created_by that names no Account, or names a machine Account, is
// not human.
type tokenMinter struct {
	accountID string
	human     bool
}

// legacyToken is the part of a tokens row the step reads.
type legacyToken struct {
	id        string
	scope     sql.NullString
	createdBy string
	expiresAt string
	revoked   bool
	maxUses   int
	uses      int
}

// copyScopeToTags is migration 33's Go step. It reads every result set fully and
// closes it before writing, because the store has one connection. Bad data in a
// token or a label is logged and skipped, never fatal: only a SQL failure, or a
// refusal by writeTagChanges that the filtering below should make impossible, aborts
// the migration and so the Relay's start.
func copyScopeToTags(ctx context.Context, tx *sql.Tx, logger *slog.Logger) error {
	accountsByName, err := readAccountsByName(ctx, tx)
	if err != nil {
		return err
	}
	tokens, err := readLegacyTokens(ctx, tx)
	if err != nil {
		return err
	}

	minters := make(map[string]tokenMinter, len(tokens))
	creators := make(map[string]string, len(tokens))
	converted := 0
	now := time.Now().UTC()
	for _, t := range tokens {
		name, _, _ := strings.Cut(t.createdBy, ":")
		acct, resolved := accountsByName[accounts.NormalizeName(name)]
		minters[t.id] = acct
		creators[t.id] = t.createdBy
		if resolved {
			if _, err := tx.ExecContext(ctx,
				`UPDATE tokens SET created_by_account_id = ?, created_by_human = ? WHERE token_id = ?`,
				acct.accountID, boolToInt(acct.human), t.id); err != nil {
				return fmt.Errorf("record minting Account on token: %w", err)
			}
		}

		var scope []string
		if t.scope.Valid {
			if err := json.Unmarshal([]byte(t.scope.String), &scope); err != nil {
				logger.Warn("upgrade: an Enrollment Token's scope could not be read; it was not converted to initial tags",
					"token_id", t.id)
				continue
			}
		}
		if !acct.human {
			if len(scope) > 0 && t.live(now) {
				logger.Warn("upgrade: an Enrollment Token a machine or unknown Account minted carries a scope that is no longer stamped; re-mint it from a human Account to tag joining Nodes",
					"token_id", t.id)
			}
			continue
		}

		// A token that has enrolled a Node is not converted: its earlier use
		// already stamped the scope, and what it may still enroll is for a person
		// to decide by minting it again.
		if t.uses > 0 {
			if len(scope) > 0 && t.live(now) {
				logger.Warn("upgrade: a used Enrollment Token keeps a scope that is no longer stamped and was not converted to initial tags; re-mint it to tag joining Nodes",
					"token_id", t.id)
			}
			continue
		}

		tags, dropped := scopeToInitialTags(scope)
		if len(dropped) > 0 {
			logger.Warn("upgrade: Enrollment Token scope entries were not converted to initial tags",
				"token_id", t.id, "keys", dropped)
		}
		if len(tags) == 0 {
			continue
		}
		encoded, err := json.Marshal(tags)
		if err != nil {
			return fmt.Errorf("encode initial tags: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE tokens SET initial_tags = ? WHERE token_id = ?`,
			string(encoded), t.id); err != nil {
			return fmt.Errorf("record initial tags on token: %w", err)
		}
		converted++
	}

	copied, listed, err := copyRelayLabelsToTags(ctx, tx, logger, minters, creators)
	if err != nil {
		return err
	}
	// A fresh database has nothing to convert and says nothing.
	if copied+listed+converted > 0 {
		logger.Info("upgrade: Enrollment Token scopes became tags",
			"tags_copied", copied, "nodes_listed", listed, "tokens_converted", converted)
	}
	return nil
}

// live reports whether the token could still enroll a Node. An expiry the step
// cannot parse counts as not live.
func (t legacyToken) live(now time.Time) bool {
	expires, err := parseTime(sql.NullString{String: t.expiresAt, Valid: true})
	if err != nil || !expires.After(now) {
		return false
	}
	return !t.revoked && (t.maxUses <= 0 || t.uses < t.maxUses)
}

// scopeToInitialTags converts a legacy scope to initial tags in written form,
// sorted by key. Entries that are not a relay: label, name relay:node-id, are
// declined by the store's tag predicate, or exceed registry.MaxTagsPerNode are
// returned in dropped, as bounded keys. The last value for a key wins, as
// SetRelayLabels stamped it.
func scopeToInitialTags(scope []string) (tags, dropped []string) {
	values := map[string]string{}
	for _, entry := range scope {
		bare, ok := strings.CutPrefix(entry, "relay:")
		if !ok {
			// Key only: the value of an entry that was never a relay: label
			// is not known to be harmless to log.
			entryKey, _, _ := strings.Cut(entry, "=")
			bounded, _ := registry.BoundLogKey(entryKey)
			dropped = append(dropped, bounded)
			continue
		}
		key, value, _ := strings.Cut(bare, "=")
		if key == registry.NodeIDKey || !tagAcceptable(key, value) {
			bounded, _ := registry.BoundLogKey(key)
			dropped = append(dropped, bounded)
			continue
		}
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		if i >= registry.MaxTagsPerNode {
			bounded, _ := registry.BoundLogKey(k)
			dropped = append(dropped, bounded)
			continue
		}
		tags = append(tags, "tag:"+k+"="+values[k])
	}
	return tags, dropped
}

// tagAcceptable reports whether the store would accept key=value as a tag: the
// one well-formedness and length predicate, registry.TagChange.Validate.
func tagAcceptable(key, value string) bool {
	return registry.TagChange{
		NodeID: "-",
		Key:    key,
		After:  registry.TagValue{Set: true, Value: value},
	}.Validate() == nil
}

// nodeRelayLabel is one row of relay_labels.
type nodeRelayLabel struct{ key, value string }

// copyRelayLabelsToTags copies each relay: label of a Node a human-minted token
// enrolled to a tag, through writeTagChanges, and logs every Node with a label it
// could not copy. It returns how many tags it copied and how many Nodes it
// listed. relay_labels is only read.
func copyRelayLabelsToTags(ctx context.Context, tx *sql.Tx, logger *slog.Logger, minters map[string]tokenMinter, creators map[string]string) (copied, listed int, err error) {
	enrolledBy, err := readNodeTokens(ctx, tx)
	if err != nil {
		return 0, 0, err
	}
	relayLabels, err := readNodeRelayLabels(ctx, tx)
	if err != nil {
		return 0, 0, err
	}
	tagCounts, tagKeys, err := readNodeTagKeys(ctx, tx)
	if err != nil {
		return 0, 0, err
	}

	var (
		changes  []registry.TagChange
		records  []audit.Record
		warnings []nodeWarning
	)
	nodeIDs := make([]string, 0, len(relayLabels))
	for id := range relayLabels {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Strings(nodeIDs)

	now := time.Now().UTC()
	for _, nodeID := range nodeIDs {
		tokenID := enrolledBy[nodeID]
		minter := minters[tokenID]
		unlisted := map[string][]string{}
		count := tagCounts[nodeID]
		for _, l := range relayLabels[nodeID] {
			bounded, _ := registry.BoundLogKey(l.key)
			var reason string
			switch {
			case l.key == registry.NodeIDKey:
				if l.value == nodeID {
					continue
				}
				reason = reasonNodeIDMismatch
			case !minter.human:
				reason = reasonMachineMinted
			case !tagAcceptable(l.key, l.value):
				reason = reasonDeclined
			case tagKeys[nodeID][l.key]:
				reason = reasonTagExists
			case count >= registry.MaxTagsPerNode:
				reason = reasonTagLimit
			}
			if reason != "" {
				unlisted[reason] = append(unlisted[reason], bounded)
				continue
			}

			change := registry.TagChange{
				NodeID: nodeID,
				Key:    l.key,
				After:  registry.TagValue{Set: true, Value: l.value},
			}
			id, err := audit.NewID()
			if err != nil {
				return 0, 0, fmt.Errorf("generate audit record id: %w", err)
			}
			name, role, _ := strings.Cut(creators[tokenID], ":")
			changes = append(changes, change)
			records = append(records, audit.Record{
				ID:        id,
				Timestamp: now,
				Kind:      audit.KindTagWrite,
				NodeID:    nodeID,
				Principal: creators[tokenID],
				Attribution: audit.Attribution{Verified: audit.Verified{
					AccountID:   minter.accountID,
					AccountName: name,
					Role:        role,
				}},
				Reason: audit.TagWriteReason(change) +
					" (upgrade: copied from Enrollment Token " + tokenID + " scope)",
			})
			count++
		}
		for _, reason := range sortedKeys(unlisted) {
			warnings = append(warnings, nodeWarning{nodeID: nodeID, reason: reason, keys: unlisted[reason]})
		}
	}

	if len(changes) > 0 {
		prepared, err := prepareTagWrite(records, changes)
		if err != nil {
			return 0, 0, fmt.Errorf("prepare copied tags: %w", err)
		}
		if err := writeTagChanges(ctx, tx, changes, prepared); err != nil {
			return 0, 0, fmt.Errorf("write copied tags: %w", err)
		}
	}

	listedNodes := map[string]struct{}{}
	for _, w := range warnings {
		listedNodes[w.nodeID] = struct{}{}
		logger.Warn("upgrade: relay: labels from an earlier Enrollment Token scope were not copied to tags; tag this Node by hand",
			"node_id", w.nodeID, "reason", w.reason, "keys", w.keys)
	}
	return len(changes), len(listedNodes), nil
}

// nodeWarning is one Node's labels left uncopied, for one reason.
type nodeWarning struct {
	nodeID string
	reason string
	keys   []string
}

func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func readAccountsByName(ctx context.Context, tx *sql.Tx) (map[string]tokenMinter, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, name_normalized, kind FROM accounts`)
	if err != nil {
		return nil, fmt.Errorf("read accounts: %w", err)
	}
	defer rows.Close()
	out := map[string]tokenMinter{}
	for rows.Next() {
		var id, name, kind string
		if err := rows.Scan(&id, &name, &kind); err != nil {
			return nil, fmt.Errorf("scan account: %w", err)
		}
		out[name] = tokenMinter{accountID: id, human: kind == "human"}
	}
	return out, rows.Err()
}

func readLegacyTokens(ctx context.Context, tx *sql.Tx) ([]legacyToken, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT token_id, scope, created_by, expires_at, revoked, max_uses, uses FROM tokens ORDER BY token_id`)
	if err != nil {
		return nil, fmt.Errorf("read tokens: %w", err)
	}
	defer rows.Close()
	var out []legacyToken
	for rows.Next() {
		var t legacyToken
		var revoked int
		if err := rows.Scan(&t.id, &t.scope, &t.createdBy, &t.expiresAt, &revoked, &t.maxUses, &t.uses); err != nil {
			return nil, fmt.Errorf("scan token: %w", err)
		}
		t.revoked = revoked != 0
		out = append(out, t)
	}
	return out, rows.Err()
}

func readNodeTokens(ctx context.Context, tx *sql.Tx) (map[string]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT node_id, enrolling_token_id FROM nodes`)
	if err != nil {
		return nil, fmt.Errorf("read nodes: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, token string
		if err := rows.Scan(&id, &token); err != nil {
			return nil, fmt.Errorf("scan node: %w", err)
		}
		out[id] = token
	}
	return out, rows.Err()
}

func readNodeRelayLabels(ctx context.Context, tx *sql.Tx) (map[string][]nodeRelayLabel, error) {
	rows, err := tx.QueryContext(ctx, `SELECT node_id, key, value FROM relay_labels ORDER BY node_id, key`)
	if err != nil {
		return nil, fmt.Errorf("read relay labels: %w", err)
	}
	defer rows.Close()
	out := map[string][]nodeRelayLabel{}
	for rows.Next() {
		var id string
		var l nodeRelayLabel
		if err := rows.Scan(&id, &l.key, &l.value); err != nil {
			return nil, fmt.Errorf("scan relay label: %w", err)
		}
		out[id] = append(out[id], l)
	}
	return out, rows.Err()
}

// readNodeTagKeys returns how many tags each Node carries and which keys.
func readNodeTagKeys(ctx context.Context, tx *sql.Tx) (counts map[string]int, keys map[string]map[string]bool, err error) {
	rows, err := tx.QueryContext(ctx, `SELECT node_id, key FROM tag_labels`)
	if err != nil {
		return nil, nil, fmt.Errorf("read tags: %w", err)
	}
	defer rows.Close()
	counts = map[string]int{}
	keys = map[string]map[string]bool{}
	for rows.Next() {
		var id, key string
		if err := rows.Scan(&id, &key); err != nil {
			return nil, nil, fmt.Errorf("scan tag: %w", err)
		}
		counts[id]++
		if keys[id] == nil {
			keys[id] = map[string]bool{}
		}
		keys[id][key] = true
	}
	return counts, keys, rows.Err()
}
