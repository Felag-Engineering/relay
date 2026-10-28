package approval

import (
	"fmt"
	"io"
)

// encoding.go is the shared preimage encoding for every content-addressed
// hash in this package: HashPlan (plan.go) and the shape keys (shape.go, D10).
// Both are LIVE STORED BINDINGS — HashPlan is written into
// approval_requests.plan_hash and consulted by capability's release lookup, and
// the shape keys are written into approval_requests.shape_key — so editing
// either primitive below
// silently re-points every hash and every shape key already on disk. That is
// exactly what TestEncodingFormatIsPinned (encoding_test.go) exists to turn
// into a failing test instead of a silent data event.
//
// The contract every construction in this package obeys, using only these two
// primitives:
//
//  1. Every field NAME is a compile-time literal. No caller-influenced byte
//     ever occupies a field name, which is what makes the key/value boundary
//     unique; folding a caller-controlled argument key into the field name
//     (write("arg."+k, v)) would make the boundary ambiguous and collidable.
//  2. Every variable-length VALUE is written as its byte length, a colon, then
//     its bytes (writeField), so the decoder always knows where a value ends
//     regardless of its contents.
//  3. Every repeated block is preceded by a \n-terminated decimal COUNT
//     (writeCount), so the number of elements is committed before any element
//     and no value can fabricate an extra one.
//  4. Consequently the preimage decodes left-to-right deterministically, and
//     two distinct hashed tuples cannot share one preimage.
//
// What these primitives do NOT decide: the FIELD SEQUENCE — which fields get
// written, in what order, and under what literal names — is each hash
// function's own. HashPlan and the shape keys each write a different first
// field from a closed, hash-specific vocabulary (kind=... for HashPlan,
// shape=2:v1 for the shape keys), so sharing this format primitive never merges
// two hash spaces into one. approval_requests still holds rows hashed under the
// kind=5:grant preimage, so HashPlan must never write that kind value; see
// TestPlanHashNeverWritesTheGrantKind and TestPlanShapeNeverWritesTheGrantDomain.

// writeField writes one variable-length field as "name=<byte length>:<bytes>\n".
func writeField(h io.Writer, field, value string) {
	fmt.Fprintf(h, "%s=%d:%s\n", field, len(value), value)
}

// writeCount writes one framing count as "name=<n>\n".
func writeCount(h io.Writer, field string, n int) {
	fmt.Fprintf(h, "%s=%d\n", field, n)
}
