package console

import (
	"bufio"
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
	defer conn.Close() //nolint:errcheck

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
	defer resp.Body.Close() //nolint:errcheck
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
