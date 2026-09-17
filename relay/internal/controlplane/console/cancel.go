package console

// cancel.go is the Console's Cancel control (#595, specs 13 and 03): a form
// on Job detail and on the Agents stream that asks the capability layer to
// stop a Job's Tasks.
//
// This is the Console's FIRST route that reaches the capability layer's
// WRITE path. Every other route in this package (seams.go's header) only
// ever reads. It is not an execution route, so it is not behind
// console_execution (see console.go's Routes and control_surfaces.go's
// wiring): ADR-0026 decision 5 scopes that flag to the composer and to
// dispatch, because its reason is the browser-borne fleet-RCE class, and
// Cancel cannot run anything — it can only ask something already running to
// stop. Cancel only ever asks: undispatched Tasks are marked cancelled,
// in-flight ones are asked over their Tunnels, and the request itself
// changes no outcome that is already true.
//
// # Import-scope
//
// This file is the Console's only importer of internal/authz, and it names
// exactly one symbol from it: the authz.ErrUnauthorized sentinel, used only
// to RECOGNIZE a refusal the capability layer already made and RENDER it.
// It never constructs, names, or calls a role gate — no_dispatch_test.go's
// authz allowlist enforces that structurally, not by convention.
//
// # Who decides
//
// The role floor (operator, for any Job — #595, execution.md §Cancellation)
// and the audit row are the capability layer's, exactly as invariant 10
// requires: this file renders what capability.Service.CancelJob decided, and
// decides nothing itself.

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/authz"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// JobCanceller is the one write seam this package holds. It lives here,
// rather than on seams.go, because seams.go's header says every seam there
// is read-only — this is deliberately the one exception, and it gets its
// own file to keep that claim true of seams.go without qualification.
//
// *capability.Service satisfies it. The single method mirrors
// capability.Service.CancelJob's signature exactly: the role floor and the
// audit row are decided and recorded there, never here.
type JobCanceller interface {
	CancelJob(ctx context.Context, p capability.Principal, jobID string) error
}

// cancelJobPattern is this route's ServeMux pattern, named so cancelOffered
// can compare it against routesFor's output rather than restating the path.
const cancelJobPattern = "POST /console/jobs/{job_id}/cancel"

// cancelJobAction builds the form action for jobID: the Console's jobs
// prefix, the id (escaped — a Job ID is Relay-minted today, but the action
// attribute must not assume that), and the cancel suffix.
func cancelJobAction(jobID string) string {
	return "/console/jobs/" + url.PathEscape(jobID) + "/cancel"
}

// JobCancel is the shared control's data: the form action and the CSRF
// token every Console POST needs. Rendered by the "job-cancel" component
// (components.go).
type JobCancel struct {
	Action    string
	CSRFToken string
}

// cancelOffered reports whether role may reach the cancel route at all. It
// goes through routesFor deliberately — console.go's own rule is that
// nothing but [Route.ReachableBy] (via routesFor) may decide reachability —
// so a drawn button and a reachable route stay one fact. This is mount-time
// absence (d.Cancel nil, or the route's own MinRole), never authorization:
// the capability layer's RoleGate is what actually refuses a request that
// reaches the handler.
func cancelOffered(d Deps, role accounts.Role) bool {
	if d.Cancel == nil {
		return false
	}
	for _, r := range routesFor(d, role) {
		if r.Pattern() == cancelJobPattern {
			return true
		}
	}
	return false
}

// handleCancelJob implements POST /console/jobs/{job_id}/cancel.
func handleCancelJob(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := principal(w, r)
		if !ok {
			return
		}
		if d.Cancel == nil {
			unavailable(w, "Job cancellation")
			return
		}
		jobID := r.PathValue("job_id")
		if jobID == "" || len(jobID) > maxJobIDBytes {
			http.NotFound(w, r)
			return
		}

		err := d.Cancel.CancelJob(r.Context(), caller, jobID)
		if err == nil {
			// Post-redirect-get, always to Job detail — never to a
			// caller-supplied return URL (no open redirect). Job detail is
			// where the honest result renders (job.go).
			http.Redirect(w, r, "/console/jobs/"+url.PathEscape(jobID), http.StatusSeeOther)
			return
		}

		pg, ok := page(d, w, r, "Cancel")
		if !ok {
			return
		}
		switch {
		case errors.Is(err, jobs.ErrJobNotFound):
			w.WriteHeader(http.StatusNotFound)
			renderScreen(w, pg, cancelResultTmpl, cancelResultView{
				Heading: "No Job with the id " + jobID + " appears in this Relay's records.",
			})
		case errors.Is(err, authz.ErrUnauthorized):
			// The capability layer made the decision; this screen only
			// renders it. Informative, not an error: nothing was stopped
			// and nothing kept running that would not have anyway.
			w.WriteHeader(http.StatusForbidden)
			renderScreen(w, pg, cancelResultTmpl, cancelResultView{
				Heading: "The Relay refused this cancel: " + err.Error() + ". The Job continues.",
			})
		default:
			w.WriteHeader(http.StatusInternalServerError)
			renderScreen(w, pg, cancelResultTmpl, cancelResultView{
				Heading:  "The cancel did not complete: " + err.Error() + ". Some Tasks may already have been stopped.",
				JobHref:  "/console/jobs/" + url.PathEscape(jobID),
				JobLabel: "Open the Job to see where each one is.",
			})
		}
	}
}

// cancelResultView is the shell rendered for a cancel that did not redirect —
// every case but success. Deliberately small: the interesting rendering
// (which Tasks read cancelled, which are still in flight) lives on Job
// detail itself (job.go), and this page exists only to say why the redirect
// did not happen.
type cancelResultView struct {
	Heading  string
	JobHref  string
	JobLabel string
}

var cancelResultTmpl = newScreen("cancel-result", `
<div class="placeholder">
  <p>{{.Heading}}</p>
  {{with .JobHref}}<p><a href="{{.}}">{{$.JobLabel}}</a></p>{{end}}
</div>
`)
