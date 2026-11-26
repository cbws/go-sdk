package externalaccount

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

const (
	testAudience       = "projects/my-project/workloadIdentityPools/ci/providers/gitlab"
	testServiceAccount = "projects/-/serviceAccounts/deploy@my-project.iam-sa.cbws.xyz"
)

// stsServer is a fake STS. It records the subject tokens it was sent and
// answers with a numbered token, or with the refusal in refuse.
type stsServer struct {
	t *testing.T

	mu        sync.Mutex
	subjects  []string
	expiresIn int
	refuse    func(w http.ResponseWriter)
}

func newSTS(t *testing.T) (*stsServer, *httptest.Server) {
	t.Helper()

	s := &stsServer{t: t, expiresIn: 600}
	server := httptest.NewServer(s)
	t.Cleanup(server.Close)

	return s, server
}

func (s *stsServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/v1alpha1/token" {
		s.t.Errorf("STS got %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)

		return
	}
	if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		s.t.Errorf("STS got Content-Type %q", got)
	}
	if err := r.ParseForm(); err != nil {
		s.t.Errorf("STS could not parse the form: %v", err)
	}

	for field, want := range map[string]string{
		"grant_type":           "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token_type":   TokenTypeJWT,
		"requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"audience":             testAudience,
	} {
		if got := r.PostForm.Get(field); got != want {
			s.t.Errorf("STS got %s %q, want %q", field, got, want)
		}
	}
	if r.PostForm.Has("actor_token") {
		s.t.Error("STS got an actor_token")
	}

	s.mu.Lock()
	s.subjects = append(s.subjects, r.PostForm.Get("subject_token"))
	issued := len(s.subjects)
	refuse, expiresIn := s.refuse, s.expiresIn
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if refuse != nil {
		refuse(w)

		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":      fmt.Sprintf("sts-%d", issued),
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"token_type":        "Bearer",
		"expires_in":        expiresIn,
	})
}

func (s *stsServer) received() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]string(nil), s.subjects...)
}

func (s *stsServer) setExpiresIn(seconds int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expiresIn = seconds
}

// writeToken writes a subject token file and returns its path.
func writeToken(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("could not write the token: %v", err)
	}

	return path
}

func fileConfig(server *httptest.Server, path string) Config {
	return Config{
		Type:             ConfigType,
		Audience:         testAudience,
		SubjectTokenType: TokenTypeJWT,
		TokenURL:         server.URL + "/v1alpha1/token",
		CredentialSource: &CredentialSource{File: path},
	}
}

func token(t *testing.T, conf Config) (*oauth2.Token, error) {
	t.Helper()

	source, err := NewTokenSource(context.Background(), conf)
	if err != nil {
		t.Fatalf("NewTokenSource: %v", err)
	}

	return source.Token()
}

// TestFileSourceExchangesWithSTS covers the plain exchange: a token file, no
// impersonation, and the STS token handed back with its expiry.
func TestFileSourceExchangesWithSTS(t *testing.T) {
	sts, server := newSTS(t)

	got, err := token(t, fileConfig(server, writeToken(t, "subject-1\n")))
	if err != nil {
		t.Fatalf("Token: %v", err)
	}

	if got.AccessToken != "sts-1" || got.TokenType != "Bearer" {
		t.Errorf("token = %q %q, want sts-1 Bearer", got.AccessToken, got.TokenType)
	}
	if remaining := time.Until(got.Expiry); remaining < 9*time.Minute || remaining > 10*time.Minute {
		t.Errorf("token expires in %s, want about 10 minutes", remaining)
	}
	if subjects := sts.received(); len(subjects) != 1 || subjects[0] != "subject-1" {
		t.Errorf("STS got subject tokens %q, want [subject-1] with the newline trimmed", subjects)
	}
}

// TestRefreshRereadsTheSubjectToken covers rotation: the replacement fetched
// ahead of expiry is exchanged with whatever the file holds by then.
func TestRefreshRereadsTheSubjectToken(t *testing.T) {
	sts, server := newSTS(t)
	// Inside the refresh window from the start, but still servable, so the
	// second call is answered at once and starts a fetch in the background.
	sts.setExpiresIn(15)
	path := writeToken(t, "subject-1")

	source, err := NewTokenSource(context.Background(), fileConfig(server, path))
	if err != nil {
		t.Fatalf("NewTokenSource: %v", err)
	}

	first, err := source.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if first.AccessToken != "sts-1" {
		t.Fatalf("first token = %q, want sts-1", first.AccessToken)
	}

	if err := os.WriteFile(path, []byte("subject-2"), 0o600); err != nil {
		t.Fatalf("could not rotate the token: %v", err)
	}
	sts.setExpiresIn(600)

	held, err := source.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if held.AccessToken != "sts-1" {
		t.Errorf("token served during the refresh = %q, want the held sts-1", held.AccessToken)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		next, err := source.Token()
		if err != nil {
			t.Fatalf("Token: %v", err)
		}
		if next.AccessToken == "sts-2" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the token was not replaced before expiry; STS got %q", sts.received())
		}
		time.Sleep(10 * time.Millisecond)
	}

	if subjects := sts.received(); len(subjects) != 2 || subjects[1] != "subject-2" {
		t.Errorf("STS got subject tokens %q, want the rotated subject-2 second", subjects)
	}
}

func TestFileSourceJSONFormat(t *testing.T) {
	sts, server := newSTS(t)

	conf := fileConfig(server, writeToken(t, `{"id_token": "subject-json", "other": 1}`))
	conf.CredentialSource.Format = &Format{Type: "json", SubjectTokenFieldName: "id_token"}

	if _, err := token(t, conf); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if subjects := sts.received(); len(subjects) != 1 || subjects[0] != "subject-json" {
		t.Errorf("STS got subject tokens %q, want [subject-json]", subjects)
	}
}

func TestFormatRefusesWhatHoldsNoToken(t *testing.T) {
	for name, tc := range map[string]struct {
		format *Format
		raw    string
	}{
		"empty text":        {raw: " \n"},
		"not JSON":          {format: &Format{Type: "json", SubjectTokenFieldName: "token"}, raw: "secret-not-json"},
		"missing field":     {format: &Format{Type: "json", SubjectTokenFieldName: "token"}, raw: `{"other": "secret-other"}`},
		"field not string":  {format: &Format{Type: "json", SubjectTokenFieldName: "token"}, raw: `{"token": 1}`},
		"empty field value": {format: &Format{Type: "json", SubjectTokenFieldName: "token"}, raw: `{"token": ""}`},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := tc.format.parse([]byte(tc.raw))
			if err == nil {
				t.Fatal("parse accepted it")
			}
			if strings.Contains(err.Error(), "secret") {
				t.Errorf("error quotes the source's output: %v", err)
			}
		})
	}
}

func TestURLSource(t *testing.T) {
	sts, server := newSTS(t)

	tokens := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Metadata-Flavor"); got != "CBWS" {
			t.Errorf("token URL got Metadata-Flavor %q, want CBWS", got)
		}
		_, _ = fmt.Fprint(w, `{"value": "subject-url"}`)
	}))
	t.Cleanup(tokens.Close)

	conf := fileConfig(server, "")
	conf.CredentialSource = &CredentialSource{
		URL:     tokens.URL,
		Headers: map[string]string{"Metadata-Flavor": "CBWS"},
		Format:  &Format{Type: "json", SubjectTokenFieldName: "value"},
	}

	if _, err := token(t, conf); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if subjects := sts.received(); len(subjects) != 1 || subjects[0] != "subject-url" {
		t.Errorf("STS got subject tokens %q, want [subject-url]", subjects)
	}
}

// TestURLSourceFailureQuotesNoBody covers a token URL that answers with an
// error: the body may hold a token, so the error reports only the status.
func TestURLSourceFailureQuotesNoBody(t *testing.T) {
	sts, server := newSTS(t)

	tokens := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "secret-in-body", http.StatusForbidden)
	}))
	t.Cleanup(tokens.Close)

	conf := fileConfig(server, "")
	conf.CredentialSource = &CredentialSource{URL: tokens.URL}

	_, err := token(t, conf)
	if err == nil {
		t.Fatal("Token succeeded")
	}
	if strings.Contains(err.Error(), "secret-in-body") {
		t.Errorf("error quotes the body: %v", err)
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error does not name the status: %v", err)
	}
	if len(sts.received()) != 0 {
		t.Error("STS was called without a subject token")
	}
}

// writeScript writes an executable shell script and returns its path.
func writeScript(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "token.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatalf("could not write the script: %v", err)
	}

	return path
}

func TestExecutableSource(t *testing.T) {
	t.Setenv(AllowExecutablesEnvVar, "1")
	sts, server := newSTS(t)

	// The script answers with what it was told, so the test sees both that
	// it ran and what environment it ran in.
	script := writeScript(t, `echo "$1:$CBWS_EXTERNAL_ACCOUNT_AUDIENCE:$CBWS_EXTERNAL_ACCOUNT_TOKEN_TYPE:$CBWS_EXTERNAL_ACCOUNT_IMPERSONATED_ACCOUNT"`)

	conf := fileConfig(server, "")
	conf.CredentialSource = &CredentialSource{Executable: &ExecutableConfig{Command: script + " subject-exec"}}

	if _, err := token(t, conf); err != nil {
		t.Fatalf("Token: %v", err)
	}

	want := "subject-exec:" + testAudience + ":" + TokenTypeJWT + ":"
	if subjects := sts.received(); len(subjects) != 1 || subjects[0] != want {
		t.Errorf("STS got subject tokens %q, want [%s]", subjects, want)
	}
}

func TestExecutableSourceNeedsToBeAllowed(t *testing.T) {
	t.Setenv(AllowExecutablesEnvVar, "")
	_, server := newSTS(t)

	conf := fileConfig(server, "")
	conf.CredentialSource = &CredentialSource{Executable: &ExecutableConfig{Command: "/bin/true"}}

	_, err := NewTokenSource(context.Background(), conf)
	if err == nil || !strings.Contains(err.Error(), AllowExecutablesEnvVar) {
		t.Fatalf("NewTokenSource = %v, want an error naming %s", err, AllowExecutablesEnvVar)
	}
}

// TestExecutableFailureQuotesNoOutput covers a command that fails after
// printing: neither stream reaches the error, since either may hold a token.
func TestExecutableFailureQuotesNoOutput(t *testing.T) {
	t.Setenv(AllowExecutablesEnvVar, "1")
	_, server := newSTS(t)

	script := writeScript(t, "echo secret-stdout\necho secret-stderr >&2\nexit 3\n")

	conf := fileConfig(server, "")
	conf.CredentialSource = &CredentialSource{Executable: &ExecutableConfig{Command: script}}

	_, err := token(t, conf)
	if err == nil {
		t.Fatal("Token succeeded")
	}
	if strings.Contains(fmt.Sprintf("%+v", err), "secret") {
		t.Errorf("error quotes the command's output: %+v", err)
	}
	if !strings.Contains(err.Error(), "exit status 3") {
		t.Errorf("error does not name the exit status: %v", err)
	}
}

type supplierFunc func(ctx context.Context, options SupplierOptions) (string, error)

func (f supplierFunc) SubjectToken(ctx context.Context, options SupplierOptions) (string, error) {
	return f(ctx, options)
}

func TestSubjectTokenSupplier(t *testing.T) {
	sts, server := newSTS(t)

	var got SupplierOptions
	conf := fileConfig(server, "")
	conf.CredentialSource = nil
	conf.SubjectTokenSupplier = supplierFunc(func(_ context.Context, options SupplierOptions) (string, error) {
		got = options

		return "subject-supplied", nil
	})

	if _, err := token(t, conf); err != nil {
		t.Fatalf("Token: %v", err)
	}

	if got != (SupplierOptions{Audience: testAudience, SubjectTokenType: TokenTypeJWT}) {
		t.Errorf("supplier got %+v", got)
	}
	if subjects := sts.received(); len(subjects) != 1 || subjects[0] != "subject-supplied" {
		t.Errorf("STS got subject tokens %q, want [subject-supplied]", subjects)
	}
}

func TestSubjectTokenSupplierFailure(t *testing.T) {
	sts, server := newSTS(t)

	conf := fileConfig(server, "")
	conf.CredentialSource = nil
	conf.SubjectTokenSupplier = supplierFunc(func(context.Context, SupplierOptions) (string, error) {
		return "", errors.New("no token today")
	})

	if _, err := token(t, conf); err == nil || !strings.Contains(err.Error(), "no token today") {
		t.Fatalf("Token = %v, want the supplier's error", err)
	}
	if len(sts.received()) != 0 {
		t.Error("STS was called without a subject token")
	}
}

// TestSTSErrors covers each refusal STS answers with: the OAuth 2.0 error
// code reaches the caller, and the subject token does not reach the message.
func TestSTSErrors(t *testing.T) {
	for _, code := range []string{
		ErrorInvalidGrant,
		ErrorUnauthorizedClient,
		ErrorInvalidRequest,
		ErrorUnsupportedGrantType,
		ErrorServerError,
	} {
		t.Run(code, func(t *testing.T) {
			sts, server := newSTS(t)
			sts.refuse = func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": "refused"})
			}

			_, err := token(t, fileConfig(server, writeToken(t, "secret-subject")))

			var retrieve *oauth2.RetrieveError
			if !errors.As(err, &retrieve) {
				t.Fatalf("Token = %v, want an *oauth2.RetrieveError", err)
			}
			if retrieve.ErrorCode != code || retrieve.ErrorDescription != "refused" {
				t.Errorf("error code %q, description %q", retrieve.ErrorCode, retrieve.ErrorDescription)
			}
			if strings.Contains(err.Error(), "secret-subject") {
				t.Errorf("error quotes the subject token: %v", err)
			}
		})
	}
}

func TestSTSErrorWithoutOAuthBody(t *testing.T) {
	sts, server := newSTS(t)
	sts.refuse = func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = fmt.Fprint(w, "upstream gone")
	}

	_, err := token(t, fileConfig(server, writeToken(t, "subject")))

	var retrieve *oauth2.RetrieveError
	if !errors.As(err, &retrieve) {
		t.Fatalf("Token = %v, want an *oauth2.RetrieveError", err)
	}
	if retrieve.ErrorCode != "" || retrieve.Response.StatusCode != http.StatusBadGateway {
		t.Errorf("error code %q, status %d", retrieve.ErrorCode, retrieve.Response.StatusCode)
	}
}

func TestSTSResponseWithoutExpiryIsRefused(t *testing.T) {
	sts, server := newSTS(t)
	sts.setExpiresIn(0)

	if _, err := token(t, fileConfig(server, writeToken(t, "subject"))); err == nil {
		t.Fatal("Token accepted a token without an expiry")
	}
}

func TestConfigValidation(t *testing.T) {
	valid := func() Config {
		return Config{
			Audience:         testAudience,
			SubjectTokenType: TokenTypeIDToken,
			CredentialSource: &CredentialSource{File: "/token"},
		}
	}

	if _, err := NewTokenSource(context.Background(), valid()); err != nil {
		t.Fatalf("a valid configuration was refused: %v", err)
	}

	for name, change := range map[string]func(*Config){
		"wrong type":               func(c *Config) { c.Type = "service_account" },
		"audience not a provider":  func(c *Config) { c.Audience = "projects/my-project/workloadIdentityPools/ci" },
		"unsupported token type":   func(c *Config) { c.SubjectTokenType = "urn:ietf:params:oauth:token-type:saml2" },
		"token URL not HTTP":       func(c *Config) { c.TokenURL = "file:///etc/passwd" },
		"account not a name":       func(c *Config) { c.ServiceAccountImpersonation = "deploy@my-project.iam-sa.cbws.xyz" },
		"account with a query":     func(c *Config) { c.ServiceAccountImpersonation = "projects/p/serviceAccounts/a?b" },
		"no source":                func(c *Config) { c.CredentialSource = nil },
		"source and supplier":      func(c *Config) { c.SubjectTokenSupplier = supplierFunc(nil) },
		"two sources":              func(c *Config) { c.CredentialSource.URL = "https://example.com" },
		"empty source":             func(c *Config) { c.CredentialSource.File = "" },
		"unknown format":           func(c *Config) { c.CredentialSource.Format = &Format{Type: "xml"} },
		"json format with no name": func(c *Config) { c.CredentialSource.Format = &Format{Type: "json"} },
	} {
		t.Run(name, func(t *testing.T) {
			conf := valid()
			change(&conf)

			if _, err := NewTokenSource(context.Background(), conf); err == nil {
				t.Error("NewTokenSource accepted it")
			}
		})
	}
}

func TestExecutableTimeoutBounds(t *testing.T) {
	t.Setenv(AllowExecutablesEnvVar, "1")

	for _, millis := range []int{4999, 120001} {
		conf := Config{
			Audience:         testAudience,
			SubjectTokenType: TokenTypeJWT,
			CredentialSource: &CredentialSource{Executable: &ExecutableConfig{Command: "/bin/true", TimeoutMillis: &millis}},
		}
		if _, err := NewTokenSource(context.Background(), conf); err == nil {
			t.Errorf("timeout_millis %d was accepted", millis)
		}
	}
}

func TestProjectName(t *testing.T) {
	for _, tc := range []struct {
		impersonation string
		want          string
	}{
		{"", "my-project"},
		{"projects/-/serviceAccounts/deploy@other.iam-sa.cbws.xyz", "my-project"},
		{"projects/other/serviceAccounts/deploy@other.iam-sa.cbws.xyz", "other"},
	} {
		conf := Config{Audience: testAudience, ServiceAccountImpersonation: tc.impersonation}
		if got := conf.ProjectName(); got != tc.want {
			t.Errorf("ProjectName() with impersonation %q = %q, want %q", tc.impersonation, got, tc.want)
		}
	}
}

// TestConfigJSON covers a configuration file as a workload writes it, with
// Google's field names.
func TestConfigJSON(t *testing.T) {
	data := `{
	  "type": "external_account",
	  "audience": "` + testAudience + `",
	  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
	  "token_url": "https://sts.example.com/v1alpha1/token",
	  "service_account_impersonation": "` + testServiceAccount + `",
	  "credential_source": {
	    "url": "http://169.254.169.254/token",
	    "headers": {"Metadata-Flavor": "CBWS"},
	    "format": {"type": "json", "subject_token_field_name": "value"}
	  }
	}`

	var conf Config
	if err := json.Unmarshal([]byte(data), &conf); err != nil {
		t.Fatalf("could not parse: %v", err)
	}

	source := conf.CredentialSource
	if conf.Type != ConfigType || conf.TokenURL != "https://sts.example.com/v1alpha1/token" ||
		conf.ServiceAccountImpersonation != testServiceAccount || source == nil ||
		source.URL != "http://169.254.169.254/token" || source.Headers["Metadata-Flavor"] != "CBWS" ||
		source.Format == nil || source.Format.SubjectTokenFieldName != "value" {
		t.Errorf("parsed %+v with source %+v", conf, source)
	}
	if _, err := NewTokenSource(context.Background(), conf); err != nil {
		t.Errorf("NewTokenSource: %v", err)
	}
}
