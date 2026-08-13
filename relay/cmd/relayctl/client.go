package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/apiclient"
)

// client.go wraps the GENERATED transport (internal/apiclient/client.gen.go)
// with the two things every command needs and the generator does not provide:
// the bearer credential on each request, and one place that turns a non-2xx
// response into a typed error carrying the Relay's own problem detail.

// apiError is a non-2xx response, carrying the server's RFC 7807 problem
// detail. The server's message states the rule that refused the request; this
// type exists to transport it, not to reinterpret it.
type apiError struct {
	Status int
	Title  string
	Detail string
}

func (e *apiError) Error() string {
	switch {
	case e.Title != "" && e.Detail != "":
		return fmt.Sprintf("%s (HTTP %d): %s", e.Title, e.Status, e.Detail)
	case e.Title != "":
		return fmt.Sprintf("%s (HTTP %d)", e.Title, e.Status)
	default:
		return fmt.Sprintf("request failed (HTTP %d)", e.Status)
	}
}

// newAPIClient builds the generated client with a request editor that attaches
// the bearer credential.
//
// The credential is attached HERE, once, rather than by each command: a command
// that forgot would silently make an unauthenticated call and get a 401 that
// looks like a configuration problem.
func newAPIClient(cfg Config) (*apiclient.Client, error) {
	hc, err := httpClient(cfg)
	if err != nil {
		return nil, err
	}
	return apiclient.NewClient(strings.TrimRight(cfg.Endpoint, "/"),
		apiclient.WithHTTPClient(hc),
		apiclient.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "Bearer "+cfg.Token)
			return nil
		}),
	)
}

// decode reads resp, returning an *apiError for any non-2xx status and
// otherwise decoding the JSON body into out (which may be nil for 204s).
//
// It always closes the body — a leaked response body on an error path is the
// kind of thing that only shows up under load, which a CLI never sees and a
// long-running caller of this package eventually would.
func decode(resp *http.Response, err error, out any) error {
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return problemFrom(resp)
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// problemFrom parses an RFC 7807 body, falling back to the bare status when the
// body is missing or not a problem document (a proxy or a crash can produce
// either, and the caller still deserves the status).
func problemFrom(resp *http.Response) error {
	e := &apiError{Status: resp.StatusCode}
	var p struct {
		Status int    `json:"status"`
		Title  string `json:"title"`
		Detail string `json:"detail"`
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err == nil && json.Unmarshal(body, &p) == nil {
		e.Title, e.Detail = p.Title, p.Detail
	}
	if e.Title == "" {
		e.Title = http.StatusText(resp.StatusCode)
	}
	return e
}

// emit writes v as human-readable lines, or as indented JSON under --json.
//
// --json prints the value the CLI decoded, not the raw response body, so the
// scripted shape is the same shape the human-readable renderer saw. A caller
// piping to jq and a caller reading the terminal are looking at one thing.
func emit(w io.Writer, g *globalFlags, v any, human func(io.Writer)) error {
	if g.jsonOut {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	human(w)
	return nil
}
