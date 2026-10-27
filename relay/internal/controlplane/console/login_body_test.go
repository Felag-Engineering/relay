package console

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

// The sign-in POST is read before anyone has authenticated, so a body that trickles in
// must be cut off, not waited on. Served over a real connection, through the fixture's
// whole middleware chain: a wrapper that hid the connection from
// http.ResponseController would silently drop the deadline, and only a real server can
// show that.
func TestConsole_TrickledSignInBodyIsCut(t *testing.T) {
	saved := unauthenticatedBodyTimeout
	unauthenticatedBodyTimeout = 300 * time.Millisecond
	t.Cleanup(func() { unauthenticatedBodyTimeout = saved })

	f := newLoginFixture(t)
	srv := httptest.NewServer(f.handler)
	t.Cleanup(srv.Close)

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	// Promise a body, send a few bytes of it, then stall.
	if _, err := fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: relay\r\n"+
		"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 1000\r\n\r\nusername=mi",
		LoginPath); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("the sign-in handler was still waiting on the trickled body after 5s")
	}
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()
	// The form never arrived, so its CSRF token cannot verify: Secure refuses.
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (the form could not be read)", resp.StatusCode, http.StatusForbidden)
	}
}

// A sign-in form is a few hundred bytes; one past the cap is refused before it is parsed,
// rather than read in full up to ParseForm's 10 MB default. The form carries a valid CSRF
// token, so the only thing that can refuse the over-cap one is the cap — and the
// same form just under it is not refused.
func TestConsole_OversizedSignInBodyIsRefused(t *testing.T) {
	f := newLoginFixture(t)

	post := func(padding int) int {
		t.Helper()
		formRec := f.do(t, httptest.NewRequest(http.MethodGet, LoginPath, nil))
		csrf := cookieNamed(formRec.Result().Cookies(), signInCSRFCookieName)
		if csrf == nil {
			t.Fatal("the sign-in form set no CSRF cookie")
		}
		body := url.Values{"csrf_token": {csrf.Value}, "username": {"mike"}, "password": {"wrong"}}.Encode()
		body += "&pad=" + strings.Repeat("a", padding-len(body)-len("&pad="))
		req := httptest.NewRequest(http.MethodPost, LoginPath, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return f.do(t, req, csrf).Code
	}

	if got := post(unauthenticatedBodyMaxBytes); got == http.StatusForbidden {
		t.Fatalf("a form exactly at the cap was refused (status %d); the control is broken", got)
	}
	if got := post(unauthenticatedBodyMaxBytes + 1); got != http.StatusForbidden {
		t.Fatalf("a form one byte past the cap: status = %d, want %d", got, http.StatusForbidden)
	}
}

// slowTagWriter holds every write for delay, then fails it if its request context
// was cancelled meanwhile. A read deadline left standing after the form was read
// cancels the request's context, so a write that outlives the deadline shows it.
type slowTagWriter struct {
	TagWriter
	delay time.Duration
}

func (s slowTagWriter) WriteTag(ctx context.Context, p capability.Principal, w capability.TagWrite) (capability.TagWriteResult, error) {
	time.Sleep(s.delay)
	if err := ctx.Err(); err != nil {
		return capability.TagWriteResult{}, err
	}
	return s.TagWriter.WriteTag(ctx, p, w)
}

// An authenticated body is read before the CSRF check, so a signed-in session that
// trickles one must be cut off like the sign-in POST. The body here is a complete
// form but for its last field, so a read that gave up and passed the half-read
// form on would verify the token and write.
func TestTags_ATrickledAuthenticatedBodyIsCutAndWritesNothing(t *testing.T) {
	saved := authenticatedBodyTimeout
	authenticatedBodyTimeout = 300 * time.Millisecond
	t.Cleanup(func() { authenticatedBodyTimeout = saved })

	tw := &fakeTagWriter{}
	f := tagLoginFixture(t, tw)
	session := signedInSession(t, f, "mike", consolePassword)
	token := renderedCSRFToken(f.do(t, httptest.NewRequest(http.MethodGet, "/console/nodes/node-web-1", nil), session).Body.String())
	if token == "" {
		t.Fatal("the Node page rendered no CSRF token")
	}
	srv := httptest.NewServer(f.handler)
	t.Cleanup(srv.Close)

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: relay\r\nCookie: %s=%s\r\n"+
		"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 100000\r\n\r\n"+
		"csrf_token=%s&op=add&label=tag%%3Aa%%3Db&node_id=node-web-1&node_id=no",
		bulkTagsAction, session.Name, session.Value, token); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("the Console was still waiting on the trickled body after 5s")
	}
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (the form could not be read)", resp.StatusCode, http.StatusBadRequest)
	}
	if n := len(tw.calls()); n != 0 {
		t.Fatalf("WriteTag was called %d times for a body that never finished", n)
	}
}

// ParseForm reads no body that is not form-encoded, so the deadline must not
// depend on the content type: a signed-in caller with the header token trickles a
// text/plain body to sign-out, whose handler never reads it, and is still cut off.
func TestConsole_ATrickledNonFormAuthenticatedBodyIsCut(t *testing.T) {
	saved := authenticatedBodyTimeout
	authenticatedBodyTimeout = 300 * time.Millisecond
	t.Cleanup(func() { authenticatedBodyTimeout = saved })

	f := tagLoginFixture(t, &fakeTagWriter{})
	session := signedInSession(t, f, "mike", consolePassword)
	token := renderedCSRFToken(f.do(t, httptest.NewRequest(http.MethodGet, "/console/nodes/node-web-1", nil), session).Body.String())
	if token == "" {
		t.Fatal("the Node page rendered no CSRF token")
	}
	srv := httptest.NewServer(f.handler)
	t.Cleanup(srv.Close)

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	start := time.Now()
	if _, err := fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: relay\r\nCookie: %s=%s\r\n%s: %s\r\n"+
		"Content-Type: text/plain\r\nContent-Length: 1000\r\n\r\nhello",
		LogoutPath, session.Name, session.Value, csrfHeaderName, token); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("the Console was still waiting on the trickled body after 5s")
	}
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (the body could not be read)", resp.StatusCode, http.StatusBadRequest)
	}
	if elapsed := time.Since(start); elapsed < authenticatedBodyTimeout {
		t.Errorf("answered after %v, before the %v deadline: something other than the deadline cut it", elapsed, authenticatedBodyTimeout)
	}
}

// The read deadline guards the read of the form and no more: a handler that
// outlives it still answers.
func TestTags_TheBodyDeadlineIsClearedOnceTheFormIsRead(t *testing.T) {
	saved := authenticatedBodyTimeout
	authenticatedBodyTimeout = 300 * time.Millisecond
	t.Cleanup(func() { authenticatedBodyTimeout = saved })

	tw := &fakeTagWriter{}
	f := newLoginFixtureWith(t, func(d *Deps) {
		d.Queries = fleetFixture().Queries
		d.Tags = slowTagWriter{TagWriter: tw, delay: 900 * time.Millisecond}
	})
	session := signedInSession(t, f, "mike", consolePassword)
	token := renderedCSRFToken(f.do(t, httptest.NewRequest(http.MethodGet, "/console/nodes/node-web-1", nil), session).Body.String())
	srv := httptest.NewServer(f.handler)
	t.Cleanup(srv.Close)

	body := url.Values{"csrf_token": {token}, "op": {"add"}, "label": {"tag:a=b"}, "node_id": {"node-web-1"}}.Encode()
	req, err := http.NewRequest(http.MethodPost, srv.URL+bulkTagsAction, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 from a write that outlived the body deadline", resp.StatusCode)
	}
	if n := len(tw.calls()); n != 1 {
		t.Fatalf("WriteTag was called %d times, want 1", n)
	}
}
