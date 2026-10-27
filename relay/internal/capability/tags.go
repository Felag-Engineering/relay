package capability

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// tags.go is the tag capability: the one write of a tag: label (TagWriter).
// Who may write, what a tag may be, the 64-per-Node cap and that every change
// is on the trail are decided here and never per interface (invariant 10,
// ADR-0050). An AI-agent surface never holds it.

// Refusals and failures of the tag capability. Their text names the rule and
// never echoes caller input into the trail.
var (
	ErrTagsUnavailable      = errors.New("capability: tag writes are not configured on this Relay")
	ErrTagNamespaceRequired = errors.New("capability: only a tag: label is written on request; node:, relay: and state: labels never are (invariant 7)")
	ErrTagMalformed         = errors.New("capability: a tag's key must be non-empty, and its key and value may hold only A-Z, a-z, 0-9, '.', '_' and '-'")
	ErrTagTooLong           = fmt.Errorf("capability: a tag's key is at most %d characters and its value at most %d", registry.MaxTagKeyLen, registry.MaxTagValueLen)
	ErrTagAddNeedsAValue    = errors.New("capability: adding a tag names tag:key=value")
	ErrTagRemoveNamesAKey   = errors.New("capability: removing a tag names tag:key, with no value")
	ErrTagOpUnknown         = errors.New("capability: a tag write is add or remove")
	ErrTagNoNodes           = errors.New("capability: a tag write names at least one Node")
	ErrTagNodeIDInvalid     = errors.New("capability: every Node ID in a tag write must be non-empty and not over-long")
	ErrTagNodeNotFound      = errors.New("capability: a tag write names a Node that is not in the registry")
	ErrTagChanged           = errors.New("capability: a tag changed while this write was being made; reload and retry")
	ErrTooManyTags          = errors.New("capability: a Node carries at most 64 tags")
	ErrTagTooManyNodes      = fmt.Errorf("capability: a tag write names at most %d Nodes", MaxTagWriteNodes)
)

// MaxTagWriteNodes is the most Node IDs one tag write may name, duplicates
// counted. How many Nodes one write may touch is decided here, so every surface
// shares the bound (invariant 10).
const MaxTagWriteNodes = 256

// TagNodesNotFoundError names the Nodes a tag write could not find, for the
// caller. It matches ErrTagNodeNotFound under errors.Is. The trail records
// ErrTagNodeNotFound's text, never the ids. NodeIDs is empty when the store
// reported a Node vanishing mid-write without saying which.
type TagNodesNotFoundError struct {
	NodeIDs []string
}

func (e *TagNodesNotFoundError) Error() string {
	if len(e.NodeIDs) == 0 {
		return ErrTagNodeNotFound.Error()
	}
	return fmt.Sprintf("%s: %s", ErrTagNodeNotFound.Error(), strings.Join(e.NodeIDs, ", "))
}

// Is reports a match with ErrTagNodeNotFound.
func (e *TagNodesNotFoundError) Is(target error) bool { return target == ErrTagNodeNotFound }

// TagOp is what a tag write does.
type TagOp string

const (
	// TagAdd sets a tag, replacing its value if the Node already carries the key.
	TagAdd TagOp = "add"
	// TagRemove removes a tag; removing an absent one is a no-op.
	TagRemove TagOp = "remove"
)

// TagWrite is one tag write over a list of Node IDs. Label is in written form:
// "tag:key=value" to add and "tag:key" to remove. The tag: prefix is mandatory
// (ADR-0020).
type TagWrite struct {
	NodeIDs []string
	Op      TagOp
	Label   string
}

// TagWriteResult says what a tag write did. Changed holds one entry per Node it
// changed, in request order; Unchanged names the Nodes that already held the
// requested state and recorded nothing.
type TagWriteResult struct {
	Changed   []registry.TagChange
	Unchanged []string
}

// ParseTagLabel parses a tag in written form for op into its bare key and
// value, so no surface parses a tag itself. The exact-case "tag:" prefix is
// required, which refuses node:, relay: and state: labels, bare terms and
// "TAG:" alike. The key and value must pass registry.WellFormedLabel, the one
// predicate for every stored Label, and the tag length bounds; nothing is
// sanitised or truncated. A remove returns an empty value.
func ParseTagLabel(op TagOp, s string) (key, value string, err error) {
	if op != TagAdd && op != TagRemove {
		return "", "", ErrTagOpUnknown
	}
	rest, ok := strings.CutPrefix(s, "tag:")
	if !ok {
		return "", "", ErrTagNamespaceRequired
	}
	if op == TagAdd {
		key, value, ok = strings.Cut(rest, "=")
		if !ok {
			return "", "", ErrTagAddNeedsAValue
		}
	} else {
		if strings.Contains(rest, "=") {
			return "", "", ErrTagRemoveNamesAKey
		}
		key = rest
	}
	if !registry.WellFormedLabel(key, value) {
		return "", "", ErrTagMalformed
	}
	if len(key) > registry.MaxTagKeyLen || len(value) > registry.MaxTagValueLen {
		return "", "", ErrTagTooLong
	}
	return key, value, nil
}

// TagWriter adds and removes tag: labels: a human Account at operator or above,
// no step-up, every change on the audit trail in the same transaction as the
// change. Construct it with NewTagWriter.
type TagWriter struct {
	control *Control
	nodes   TagNodeReader
	rec     TagWriteRecorder
}

// NewTagWriter returns a TagWriter over control and nodes. It requires a real
// Authorizer and an AuditSink that is also a TagWriteRecorder, read through
// control, so there is one Recorder and one trail: an un-floored or unaudited
// tag write is a composition-root bug and panics.
func NewTagWriter(control *Control, nodes TagNodeReader) *TagWriter {
	if control == nil {
		panic("capability: NewTagWriter: control must not be nil")
	}
	if nodes == nil {
		panic("capability: NewTagWriter: node reader must not be nil")
	}
	if _, ok := control.authz.(allowAllAuthorizer); ok {
		panic("capability: NewTagWriter: requires a real Authorizer (NewControl); allowAllAuthorizer would fail open on every tag write")
	}
	if _, ok := control.rec.audit.(noopAuditSink); ok {
		panic("capability: NewTagWriter: requires a real AuditSink (NewRecorder); noopAuditSink would record no tag change")
	}
	rec, ok := control.rec.audit.(TagWriteRecorder)
	if !ok {
		panic("capability: NewTagWriter: the AuditSink must also be a TagWriteRecorder; without it a change cannot be recorded atomically")
	}
	return newTagWriter(control, nodes, rec)
}

// newTagWriter assembles a TagWriter with no checks. Only NewTagWriter and
// _test.go files call it.
func newTagWriter(control *Control, nodes TagNodeReader, rec TagWriteRecorder) *TagWriter {
	return &TagWriter{control: control, nodes: nodes, rec: rec}
}

// WriteTag adds or removes one tag on every Node in req.NodeIDs, all or
// nothing. A Node already in the requested state is reported in Unchanged and
// records nothing; when every Node is, nothing is recorded at all.
//
// Authorization runs first, so a refused caller learns nothing about the label
// rules. Every refusal (role, human-only, a label that is not a well-formed
// tag, no Node, more than MaxTagWriteNodes Nodes, an unknown Node, the 64-tag
// cap) is audited as a refusal through refuseControl. A store conflict (ErrTagChanged) changed nothing and
// is returned unaudited. No step-up evidence is consulted.
func (w *TagWriter) WriteTag(ctx context.Context, p Principal, req TagWrite) (TagWriteResult, error) {
	if w.nodes == nil || w.rec == nil {
		return TagWriteResult{}, ErrTagsUnavailable
	}
	if err := w.control.authz.AuthorizeControl(withoutAssertions(ctx), p, ControlTagWrite); err != nil {
		return TagWriteResult{}, w.control.rec.refuseControl(ctx, p, err)
	}
	key, value, err := ParseTagLabel(req.Op, req.Label)
	if err != nil {
		return TagWriteResult{}, w.control.rec.refuseControl(ctx, p, err)
	}
	ids, err := tagNodeIDs(req.NodeIDs)
	if err != nil {
		return TagWriteResult{}, w.control.rec.refuseControl(ctx, p, err)
	}

	var (
		missing   []string
		changes   []registry.TagChange
		unchanged []string
		overCap   bool
	)
	after := registry.TagValue{Set: req.Op == TagAdd, Value: value}
	for _, id := range ids {
		n, ok := w.nodes.Get(id)
		if !ok {
			missing = append(missing, id)
			continue
		}
		stored, has := n.TagLabels[key]
		before := registry.TagValue{Set: has, Value: stored}
		if before == after {
			unchanged = append(unchanged, id)
			continue
		}
		if after.Set && !has && len(n.TagLabels) >= registry.MaxTagsPerNode {
			overCap = true
		}
		changes = append(changes, registry.TagChange{NodeID: id, Key: key, Before: before, After: after})
	}
	if len(missing) > 0 {
		return TagWriteResult{}, errors.Join(&TagNodesNotFoundError{NodeIDs: missing},
			w.control.rec.refuseControl(ctx, p, ErrTagNodeNotFound))
	}
	if overCap {
		return TagWriteResult{}, w.control.rec.refuseControl(ctx, p, ErrTooManyTags)
	}
	if len(changes) == 0 {
		return TagWriteResult{Changed: []registry.TagChange{}, Unchanged: unchanged}, nil
	}

	err = w.rec.RecordTagWrite(ctx, TagWriteEvent{Principal: p, Changes: changes, Asserted: AssertionsFromContext(ctx)})
	switch {
	case err == nil:
		return TagWriteResult{Changed: changes, Unchanged: unchanged}, nil
	case errors.Is(err, ErrTagChanged):
		return TagWriteResult{}, ErrTagChanged
	case errors.Is(err, ErrTooManyTags):
		return TagWriteResult{}, w.control.rec.refuseControl(ctx, p, ErrTooManyTags)
	case errors.Is(err, ErrTagNodeNotFound):
		// A Node vanished between the read and the write; the store does not say which.
		return TagWriteResult{}, errors.Join(&TagNodesNotFoundError{},
			w.control.rec.refuseControl(ctx, p, ErrTagNodeNotFound))
	default:
		return TagWriteResult{}, fmt.Errorf("capability: record tag write: %w", err)
	}
}

// CheckInitialTags decides, ahead of any enrollment side effect, whether the
// Account that minted an Enrollment Token may write its initial tags and whether
// they hold. It is the first half of WriteInitialTags and the same decision, so
// a refusal that is certain is reached before the use is counted, the
// certificate signed or the Node recorded. A refusal is audited.
func (w *TagWriter) CheckInitialTags(ctx context.Context, minter Principal, tags []string) error {
	if len(tags) == 0 {
		return nil
	}
	_, err := w.checkInitialTags(ctx, minter, tags)
	return err
}

func (w *TagWriter) checkInitialTags(ctx context.Context, minter Principal, tags []string) (map[string]string, error) {
	if w.nodes == nil || w.rec == nil {
		return nil, ErrTagsUnavailable
	}
	if err := w.control.authz.AuthorizeControl(withoutAssertions(ctx), minter, ControlTagWrite); err != nil {
		return nil, w.control.rec.refuseControl(ctx, minter, err)
	}
	parsed, err := registry.ParseInitialTags(tags)
	if err != nil {
		return nil, w.control.rec.refuseControl(ctx, minter, err)
	}
	return parsed, nil
}

// initialTagProvenance is the suffix that distinguishes a tag written at
// enrollment from one the minter wrote live: the bearer of the join string, not
// the Account itself, caused the write. It names the token by its public ID and
// never by its secret.
func initialTagProvenance(tokenID string) string {
	return "(initial tag from Enrollment Token " + tokenID + ")"
}

// WriteInitialTags writes an Enrollment Token's initial tags on the Node its
// enrollment just recorded, as the act of the Account that minted the token, as
// recorded at mint (ADR-0050 decision 3). All land with one tag_write record
// each, naming the token, or none do. Who may write a tag stays decided by the
// Authorizer's ControlTagWrite row, so a machine or sub-operator minter writes
// nothing and the refusal is audited.
func (w *TagWriter) WriteInitialTags(ctx context.Context, minter Principal, tokenID, nodeID string, tags []string) error {
	if len(tags) == 0 {
		return nil
	}
	parsed, err := w.checkInitialTags(ctx, minter, tags)
	if err != nil {
		return err
	}
	if validateNodeID(nodeID) != nil {
		return w.control.rec.refuseControl(ctx, minter, ErrTagNodeIDInvalid)
	}
	n, ok := w.nodes.Get(nodeID)
	if !ok {
		return w.control.rec.refuseControl(ctx, minter, ErrTagNodeNotFound)
	}

	keys := make([]string, 0, len(parsed))
	for k := range parsed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var changes []registry.TagChange
	added := 0
	for _, k := range keys {
		stored, has := n.TagLabels[k]
		if has && stored == parsed[k] {
			continue
		}
		if !has {
			added++
		}
		changes = append(changes, registry.TagChange{
			NodeID: nodeID,
			Key:    k,
			Before: registry.TagValue{Set: has, Value: stored},
			After:  registry.TagValue{Set: true, Value: parsed[k]},
		})
	}
	if added+len(n.TagLabels) > registry.MaxTagsPerNode {
		return w.control.rec.refuseControl(ctx, minter, ErrTooManyTags)
	}
	if len(changes) == 0 {
		return nil
	}

	err = w.rec.RecordTagWrite(ctx, TagWriteEvent{Principal: minter, Changes: changes, Provenance: initialTagProvenance(tokenID)})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrTagChanged):
		return ErrTagChanged
	case errors.Is(err, ErrTooManyTags):
		return w.control.rec.refuseControl(ctx, minter, ErrTooManyTags)
	case errors.Is(err, ErrTagNodeNotFound):
		return errors.Join(&TagNodesNotFoundError{}, w.control.rec.refuseControl(ctx, minter, ErrTagNodeNotFound))
	default:
		return fmt.Errorf("capability: record tag write: %w", err)
	}
}

// tagNodeIDs validates and de-duplicates ids, keeping first-seen order.
func tagNodeIDs(ids []string) ([]string, error) {
	if len(ids) == 0 {
		return nil, ErrTagNoNodes
	}
	if len(ids) > MaxTagWriteNodes {
		return nil, ErrTagTooManyNodes
	}
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if validateNodeID(id) != nil {
			return nil, ErrTagNodeIDInvalid
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}
