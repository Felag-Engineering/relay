package relaytest

import "net/http"

// BearerRoundTripper injects "Authorization: Bearer <token>" on every
// request, so an *http.Client using it authenticates against the
// control-plane Authenticator.Middleware the same way every real caller
// does.
type BearerRoundTripper struct {
	Base  http.RoundTripper
	Token string
}

func (rt BearerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+rt.Token)
	return rt.Base.RoundTrip(req)
}
