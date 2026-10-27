package audit

import (
	"fmt"
	"strconv"

	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// TagWriteReason renders a tag_write record's Reason. A set value is quoted and
// an absent one is the literal (none), so an empty value and an absent one never
// read alike. Every writer of a tag_write record renders its Reason here, so the
// trail has one format.
//
//	tag:<key> old="<value>" new="<value>"
//	tag:<key> old=(none) new="<value>"
func TagWriteReason(c registry.TagChange) string {
	render := func(v registry.TagValue) string {
		if !v.Set {
			return "(none)"
		}
		return strconv.Quote(v.Value)
	}
	return fmt.Sprintf("tag:%s old=%s new=%s", c.Key, render(c.Before), render(c.After))
}
