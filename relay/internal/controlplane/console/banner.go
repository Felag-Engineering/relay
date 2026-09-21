package console

// banner.go fills the one slot in which the Console speaks about THE CONTROL
// PLANE rather than about Nodes.
//
// Every other surface answers one of the four questions, and the four questions
// are questions about machines. That leaves the product's two most catastrophic
// failure modes with nowhere to appear: the fleet-wide Freeze, and the
// certificates every other screen silently depends on. A Console full of green
// Nodes while dispatch is halted is the failure this slot exists to prevent.
//
// Nothing here is configuration and nothing here is editable (invariant 11).
// These are operational alarms.

import "net/http"

// banner returns the control-plane condition to render above content, or nil.
//
// Only one banner shows, in descending urgency, because two stacked alarms
// train an operator to dismiss the strip. Freeze outranks the certificate
// warnings: it is happening now, and they are warnings about later.
func banner(d Deps, r *http.Request) *Banner {
	if d.Freeze == nil {
		return nil
	}
	frozen, err := d.Freeze.Frozen(r.Context())
	if err != nil {
		// A Freeze we cannot read is reported as a Freeze we cannot read, not
		// as "not frozen". The whole value of an emergency stop is that its
		// state is never guessed, and the guess that costs least here is the
		// one that makes somebody look.
		return &Banner{
			Kind: BannerFreeze,
			Text: "Freeze state could not be read.",
			Detail: "The Console cannot currently tell whether dispatch is halted. " +
				"Check the Relay's logs before assuming the fleet is accepting work.",
		}
	}
	if !frozen {
		return nil
	}
	// State what is STILL TRUE. An emergency stop that reads as a total outage
	// gets released in a panic by the next person to look at it, which is
	// exactly the moment nobody should be releasing it.
	return &Banner{
		Kind: BannerFreeze,
		Text: "Freeze engaged — no new Tasks are dispatching.",
		Detail: "In-flight Tasks keep running and Preflights still resolve, so you can " +
			"still see what would happen. An admin releases it with a reason.",
	}
}
