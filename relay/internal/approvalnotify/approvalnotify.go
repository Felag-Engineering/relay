// Package approvalnotify pushes a Relay-authored notice to an operator's own
// notification plumbing when a dispatch parks for approval (ADR-0027).
//
// It is the *delivery* half of the out-of-band envelope, and the distinction
// from the *decision* half is the whole reason this package is as small and as
// weak as it is:
//
//   - **Outbound only.** Nothing here accepts an answer. A decision lands on the
//     authenticated /api/v1 endpoint, carrying an Account credential the
//     requesting session does not hold. If this package could receive
//     decisions, the guarantee would rest on whoever can forge a callback.
//   - **Best-effort.** One attempt, a bounded deadline, no retries, no queue.
//     A park is already durable, audited, and visible in the approval queue
//     before this runs. Losing a notification costs an approver a poll; it can
//     never cost safety, and building a delivery guarantee here would put a
//     store-and-forward mechanism inside a control plane that deliberately has
//     none (ADR-0004).
//   - **Never blocking.** NotifyParked returns immediately. A dispatch parking
//     must not be able to stall on someone else's HTTP server.
//
// # What leaves the Relay
//
// The body carries the Relay-authored plan summary, which includes the
// Operation's ARGUMENTS — because arguments are what the approver is deciding
// about, and an approval request that hid them would be the approval-view
// fidelity gap with extra steps. It carries no credential, no token, no captured
// output, and no Node facts beyond the sampled Node IDs already in the summary.
//
// That still makes the configured endpoint a disclosure boundary: point it at
// infrastructure trusted with the same material as the audit trail. The known
// residual that a secret passed as an Operation ARGUMENT reaches the audit trail
// verbatim (capability.Execution.Run) reaches this body by the same route.
//
// # Signing
//
// With a secret configured, each body is signed HMAC-SHA256 over
// "<timestamp>.<body>" and the receiver can verify both authenticity and
// freshness. This authenticates the RELAY TO THE RECEIVER — it is not an
// authorization mechanism and it does not make a callback trustworthy, because
// there is no callback.
package approvalnotify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

// DefaultTimeout bounds one delivery attempt end to end.
const DefaultTimeout = 5 * time.Second

// maxSecretBytes bounds a secret file. A shared secret is short; the bound
// stops a wrong path (a log, a device) from being read into memory.
const maxSecretBytes = 4096

// Header names carried on every notification.
const (
	// HeaderSignature is "sha256=<hex>" over "<timestamp>.<body>".
	HeaderSignature = "Relay-Signature"
	// HeaderTimestamp is the Unix-second timestamp the signature covers, so a
	// receiver can reject a replayed body without tracking every id it saw.
	HeaderTimestamp = "Relay-Timestamp"
	// HeaderEvent names the notification kind, so one endpoint can serve more
	// than this one event later without guessing from the body's shape.
	HeaderEvent = "Relay-Event"
)

// EventApprovalRequested is the only event this package sends today.
const EventApprovalRequested = "approval.requested"

// Config is the notifier's startup configuration. Like the approval-gate file
// it comes from the Relay's configuration file and is unreachable through any
// API (invariant 11): an endpoint that could repoint its own approval
// notifications could route them to itself.
type Config struct {
	// URL is the endpoint to POST to. HTTPS is required except on loopback,
	// where a local sidecar over HTTP is a normal deployment and the traffic
	// does not leave the host. The URL may carry a token, so it is never
	// logged or put in an error.
	URL string

	// Secret is the shared signing secret, already read through the file check
	// (ReadSecretFile) by the composition root. Empty sends unsigned
	// notifications.
	Secret []byte

	// Timeout bounds one attempt. Zero means DefaultTimeout.
	Timeout time.Duration
}

// Notifier implements capability.ApprovalNotifier over HTTP.
type Notifier struct {
	url     string
	secret  []byte
	client  *http.Client
	log     *slog.Logger
	timeout time.Duration

	// now is a clock seam so a test can pin the signed timestamp.
	now func() time.Time
}

var _ capability.ApprovalNotifier = (*Notifier)(nil)

// Option configures a Notifier. Test seams only — production wiring passes
// none.
type Option func(*Notifier)

// WithHTTPClient overrides the default client. Used by tests to point at an
// httptest server; a caller supplying one owns its timeouts and its redirect
// policy.
func WithHTTPClient(c *http.Client) Option {
	return func(n *Notifier) { n.client = c }
}

// WithLogger overrides the default logger.
func WithLogger(l *slog.Logger) Option {
	return func(n *Notifier) { n.log = l }
}

// WithClock overrides the timestamp source.
func WithClock(now func() time.Time) Option {
	return func(n *Notifier) { n.now = now }
}

// New validates cfg and returns a Notifier.
//
// A configured-but-invalid notifier is an ERROR, never a silently disabled one.
// The asymmetry mirrors the approval-gate loader: not configuring notification
// is a choice an operator makes explicitly, but asking for it and not getting it
// would leave them believing they will be paged when a fleet action parks.
func New(cfg Config, opts ...Option) (*Notifier, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("approvalnotify: url is required")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		// No %w: a *url.Error embeds the URL.
		return nil, errors.New("approvalnotify: url could not be parsed")
	}
	if err := checkScheme(u); err != nil {
		return nil, err
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	n := &Notifier{
		url:     cfg.URL,
		secret:  bytes.Clone(cfg.Secret),
		client:  &http.Client{Timeout: timeout, CheckRedirect: refuseRedirect},
		log:     slog.Default(),
		timeout: timeout,
		now:     func() time.Time { return time.Now().UTC() },
	}

	for _, o := range opts {
		o(n)
	}
	return n, nil
}

// refuseRedirect returns a 3xx to the caller unfollowed. A Relay-authored
// notice goes to the one endpoint the host configured and nowhere the receiver
// points it; the Location header is never read or logged.
func refuseRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// checkScheme requires HTTPS off-host. A plaintext notification to a remote
// endpoint would put the Relay-authored plan summary — Operation, arguments,
// and the Nodes it targets — on the wire in clear, and would let anyone on the
// path forge one.
func checkScheme(u *url.URL) error {
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopback(u.Hostname()) {
			return nil
		}
		return errors.New("approvalnotify: url is plaintext http to a non-loopback host — " +
			"an approval notice carries the Operation, its arguments, and the Nodes it targets")
	default:
		return errors.New("approvalnotify: url scheme is not https")
	}
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// ReadSecretFile loads a secret file (the signing secret, or the webhook URL
// when it is given by file) with the same fail-closed posture the
// approval-gate loader uses: no symlink following, checks on the open
// descriptor rather than the path, and a refusal for anything group- or
// world-READABLE. The permission bar is stricter than the gate file's because
// this is secret material, not configuration. It is the reader the composition
// root passes to relayconfig.Config.ResolveSecrets; its errors name the path
// and the mode, never the content.
func ReadSecretFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NOCTTY, 0) //nolint:gosec // G304: an operator-set host path (invariant 11), opened O_NOFOLLOW
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("approvalnotify: secret file %s does not exist: %w", path, fs.ErrNotExist)
		}
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("approvalnotify: secret file %s is a symlink — it must be a regular root-owned file", path)
		}
		return nil, fmt.Errorf("approvalnotify: open secret file %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // read-only

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("approvalnotify: stat secret file %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("approvalnotify: secret file %s is not a regular file (mode %s)", path, info.Mode())
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("approvalnotify: secret file %s is group- or world-accessible (mode %04o) — "+
			"it is signing key material and must be readable only by its owner (chmod 0600)", path, perm)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxSecretBytes+1))
	if err != nil {
		return nil, fmt.Errorf("approvalnotify: read secret file %s: %w", path, err)
	}
	if len(data) > maxSecretBytes {
		return nil, fmt.Errorf("approvalnotify: secret file %s is larger than the %d-byte limit", path, maxSecretBytes)
	}
	secret := bytes.TrimSpace(data)
	if len(secret) == 0 {
		return nil, fmt.Errorf("approvalnotify: secret file %s is empty", path)
	}
	return secret, nil
}

// payload is the notification body. Field names are snake_case to match the
// Control API's JSON, so an integrator reads one vocabulary across both.
//
// decision_url points at the Control API route that ANSWERS this request. It is
// a convenience for building a link, not a capability: following it still
// requires an Account credential and still lands on the authenticated endpoint.
type payload struct {
	Event         string   `json:"event"`
	RequestID     string   `json:"request_id"`
	PlanHash      string   `json:"plan_hash"`
	Summary       string   `json:"summary"`
	RequestedBy   string   `json:"requested_by"`
	MatchedRules  []string `json:"matched_rules,omitempty"`
	Progress      string   `json:"progress"`
	RequiredCount int      `json:"required_count"`
	Channel       string   `json:"channel"`
	ExpiresAt     string   `json:"expires_at"`
	DecisionPath  string   `json:"decision_path"`
}

// NotifyParked implements capability.ApprovalNotifier.
//
// It returns immediately and delivers on its own goroutine with its own
// deadline, detached from the caller's context: the request that parked is
// about to return to its client, and cancelling delivery when it does would
// mean the notification almost never went out.
func (n *Notifier) NotifyParked(ctx context.Context, notice capability.ApprovalNotice) {
	body, err := json.Marshal(payload{
		Event:         EventApprovalRequested,
		RequestID:     notice.RequestID,
		PlanHash:      notice.PlanHash,
		Summary:       notice.Summary,
		RequestedBy:   notice.RequestedBy,
		MatchedRules:  notice.Rules,
		Progress:      notice.Progress,
		RequiredCount: notice.Count,
		Channel:       notice.Channel,
		ExpiresAt:     notice.ExpiresAt.UTC().Format(time.RFC3339),
		DecisionPath:  "/api/v1/approvals/" + notice.RequestID + "/decision",
	})
	if err != nil {
		n.log.Error("approval webhook: marshal notice", "request_id", notice.RequestID, "err", err)
		return
	}

	// WithoutCancel, not the raw ctx: the values (trace context, and anything a
	// later interceptor adds) are worth keeping, the caller's cancellation is
	// not. The deadline below is this delivery's own.
	go n.deliver(context.WithoutCancel(ctx), notice.RequestID, body)
}

func (n *Notifier) deliver(ctx context.Context, requestID string, body []byte) {
	ctx, cancel := context.WithTimeout(ctx, n.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		// err is a *url.Error carrying the URL, so it is not logged.
		n.log.Error("approval webhook: build request failed", "request_id", requestID)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderEvent, EventApprovalRequested)

	if len(n.secret) > 0 {
		ts := strconv.FormatInt(n.now().Unix(), 10)
		req.Header.Set(HeaderTimestamp, ts)
		req.Header.Set(HeaderSignature, "sha256="+sign(n.secret, ts, body))
	}

	resp, err := n.client.Do(req)
	if err != nil {
		n.log.Warn("approval webhook: delivery failed",
			"request_id", requestID, "reason", deliveryFailure(err))
		return
	}
	defer resp.Body.Close() //nolint:errcheck
	// Drain a bounded prefix so the connection can be reused; the response body
	// is never parsed. Nothing the receiver says can change the Relay's state —
	// a decision has exactly one door, and this is not it.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		n.log.Warn("approval webhook: endpoint refused the notice",
			"request_id", requestID, "status", resp.StatusCode)
	}
}

// Sign returns the hex HMAC-SHA256 of "<timestamp>.<body>" under secret — the
// value a receiver recomputes to verify a notification. Exported so a receiver
// written in Go, and this package's own tests, verify with the same code the
// sender used rather than a prose description of it.
func Sign(secret []byte, timestamp string, body []byte) string {
	return sign(secret, timestamp, body)
}

func sign(secret []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// deliveryFailure names why a delivery failed as one fixed category, never
// text taken from err. The inner errors are not safe to log either: a
// *net.DNSError names the host and an x509.HostnameError names it as well. A
// category is the only form that cannot carry the URL or any part of it.
func deliveryFailure(err error) string {
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "name lookup failed"
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return "timed out"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection refused"
	}
	var verify *tls.CertificateVerificationError
	var record tls.RecordHeaderError
	if errors.As(err, &verify) || errors.As(err, &record) {
		return "tls handshake failed"
	}
	return "transport error"
}
