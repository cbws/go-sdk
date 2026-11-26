package externalaccount

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.cbws.cloud/sdk/internal/useragent"

	"golang.org/x/oauth2"
)

// maximumResponseSize bounds what is read from STS.
const maximumResponseSize = 1 << 20

// The error codes STS answers with, in the error field of an
// oauth2.RetrieveError.
const (
	// ErrorInvalidGrant is a subject token STS did not accept: one that is
	// malformed, expired, or not issued for the provider in the audience.
	ErrorInvalidGrant = "invalid_grant"

	// ErrorUnauthorizedClient is a subject token the provider's attribute
	// condition refused.
	ErrorUnauthorizedClient = "unauthorized_client"

	// ErrorInvalidRequest is an exchange request STS could not read.
	ErrorInvalidRequest = "invalid_request"

	// ErrorUnsupportedGrantType is a grant type STS does not serve.
	ErrorUnsupportedGrantType = "unsupported_grant_type"

	// ErrorServerError is a failure inside STS.
	ErrorServerError = "server_error"
)

// stsSource exchanges a fresh subject token for an STS token on every call.
type stsSource struct {
	ctx              context.Context
	tokenURL         string
	audience         string
	subjectTokenType string
	supplier         SubjectTokenSupplier
}

// Token exchanges the current subject token. An STS refusal is returned as
// an *oauth2.RetrieveError whose ErrorCode is one of the Error constants.
func (s stsSource) Token() (*oauth2.Token, error) {
	subjectToken, err := s.supplier.SubjectToken(s.ctx, SupplierOptions{
		Audience:         s.audience,
		SubjectTokenType: s.subjectTokenType,
	})
	if err != nil {
		return nil, fmt.Errorf("externalaccount: %w", err)
	}

	form := url.Values{}
	form.Set("grant_type", grantTypeExchange)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", s.subjectTokenType)
	form.Set("requested_token_type", tokenTypeAccessToken)
	form.Set("audience", s.audience)

	req, err := http.NewRequestWithContext(s.ctx, http.MethodPost, s.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("externalaccount: could not request a token from STS: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, body, err := do(s.ctx, req)
	if err != nil {
		return nil, fmt.Errorf("externalaccount: could not reach STS: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("externalaccount: STS refused the exchange: %w", retrieveError(resp, body))
	}

	var fields struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
		ExpiresIn       int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, errors.New("externalaccount: STS answered with a body that is not a token response")
	}

	// A token without an expiry reads as one that never expires to
	// golang.org/x/oauth2 and everything built on it, so one is refused
	// rather than handed on.
	if fields.AccessToken == "" || fields.ExpiresIn <= 0 {
		return nil, errors.New("externalaccount: STS returned no access token or no expiry")
	}

	return &oauth2.Token{
		AccessToken: fields.AccessToken,
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Duration(fields.ExpiresIn) * time.Second),
	}, nil
}

// do sends req with the HTTP client in ctx and reads the response body,
// bounded by maximumResponseSize.
func do(ctx context.Context, req *http.Request) (*http.Response, []byte, error) {
	resp, err := oauth2.NewClient(useragent.Context(ctx), nil).Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maximumResponseSize))
	if err != nil {
		return nil, nil, err
	}

	return resp, body, nil
}

// retrieveError reports an STS refusal. The RFC 6749 error fields are filled
// in when the body carries them, so that the error's message names the
// refusal rather than quoting the body.
func retrieveError(resp *http.Response, body []byte) *oauth2.RetrieveError {
	var fields struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		ErrorURI         string `json:"error_uri"`
	}
	_ = json.Unmarshal(body, &fields) // a body that is not an RFC 6749 error leaves them empty

	return &oauth2.RetrieveError{
		Response:         resp,
		Body:             body,
		ErrorCode:        fields.Error,
		ErrorDescription: fields.ErrorDescription,
		ErrorURI:         fields.ErrorURI,
	}
}
