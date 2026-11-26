package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"go.cbws.cloud/sdk/oauth2/externalaccount"
	"go.cbws.cloud/sdk/oauth2/tokencache"

	"golang.org/x/oauth2"
)

const externalAudience = "projects/pool-project/workloadIdentityPools/ci/providers/gitlab"

// fakeSTS answers every exchange with a token and records the subject tokens
// it was sent.
type fakeSTS struct {
	mu       sync.Mutex
	subjects []string
}

func (s *fakeSTS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()

	s.mu.Lock()
	s.subjects = append(s.subjects, r.PostForm.Get("subject_token"))
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "sts-token",
		"token_type":   "Bearer",
		"expires_in":   600,
	})
}

// externalAccountFile writes an external account configuration whose subject
// token is subject, and returns the configuration and its path.
func externalAccountFile(t *testing.T, tokenURL, iamEndpoint, subject, impersonation string) ([]byte, string) {
	t.Helper()

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte(subject), 0o600); err != nil {
		t.Fatalf("could not write the token: %v", err)
	}

	data, err := json.Marshal(externalaccount.Config{
		Type:                        externalaccount.ConfigType,
		Audience:                    externalAudience,
		SubjectTokenType:            externalaccount.TokenTypeJWT,
		TokenURL:                    tokenURL,
		ServiceAccountImpersonation: impersonation,
		IAMEndpoint:                 iamEndpoint,
		CredentialSource:            &externalaccount.CredentialSource{File: tokenPath},
	})
	if err != nil {
		t.Fatalf("could not encode the configuration: %v", err)
	}

	path := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("could not write the configuration: %v", err)
	}

	return data, path
}

// TestFindDefaultCredentialsUsesExternalAccount covers a CI job: the
// credentials variable names an external account configuration, which is
// found exactly as a key file would be.
func TestFindDefaultCredentialsUsesExternalAccount(t *testing.T) {
	isolate(t)

	sts := &fakeSTS{}
	server := httptest.NewServer(sts)
	t.Cleanup(server.Close)

	_, path := externalAccountFile(t, server.URL, "", "subject-ci", "")
	t.Setenv("CBWS_CREDENTIALS", path)

	credentials, err := FindDefaultCredentials(context.Background(), "cbws.iam")
	if err != nil {
		t.Fatalf("FindDefaultCredentials: %v", err)
	}
	if credentials.Kind() != KindExternalAccount {
		t.Errorf("Kind() = %v, want KindExternalAccount", credentials.Kind())
	}
	if len(credentials.JSON) == 0 {
		t.Error("credentials carry no JSON")
	}

	token, err := credentials.TokenSource.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if token.AccessToken != "sts-token" {
		t.Errorf("token = %q, want sts-token", token.AccessToken)
	}
	if len(sts.subjects) != 1 || sts.subjects[0] != "subject-ci" {
		t.Errorf("STS got subject tokens %q", sts.subjects)
	}

	project, err := credentials.ProjectName(context.Background())
	if err != nil || project != "pool-project" {
		t.Errorf("ProjectName() = %q, %v, want pool-project", project, err)
	}
}

func TestNewFromJSONRefusesAnUnknownType(t *testing.T) {
	_, err := NewFromJSON(context.Background(), []byte(`{"type": "authorized_user"}`), nil)
	if err == nil || !strings.Contains(err.Error(), "authorized_user") {
		t.Fatalf("NewFromJSON = %v, want an error naming the type", err)
	}
}

func TestNewFromJSONReportsAnInvalidExternalAccount(t *testing.T) {
	_, err := NewFromJSON(context.Background(), []byte(`{"type": "external_account", "audience": "nope"}`), nil)
	if err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("NewFromJSON = %v, want an error naming the audience", err)
	}
}

// TestExternalAccountCacheKey covers what an external account's tokens are
// cached under: the token URL, the provider and the target account, and
// never the subject token.
func TestExternalAccountCacheKey(t *testing.T) {
	const target = "projects/-/serviceAccounts/deploy@app.iam-sa.cbws.xyz"
	scopes := []string{"cbws.iam"}

	// Nothing answers at either endpoint: the key is looked up before any
	// fetch, which is all this test needs.
	const tokenURL = "http://127.0.0.1:1/v1alpha1/token"

	// lookedUp returns the id the source looked its token up under.
	lookedUp := func(t *testing.T, subject, impersonation string, options ...Option) string {
		t.Helper()

		data, _ := externalAccountFile(t, tokenURL, "127.0.0.1:1", subject, impersonation)
		cache := &loadRecordingCache{countingCache: newCountingCache()}
		credentials, err := NewFromJSONWithOptions(context.Background(), data, scopes, append(options, WithTokenCache(cache))...)
		if err != nil {
			t.Fatalf("NewFromJSONWithOptions: %v", err)
		}
		_, _ = credentials.TokenSource.Token()

		if len(cache.loads) != 1 {
			t.Fatalf("cache was looked up %d times, want once", len(cache.loads))
		}

		return cache.loads[0]
	}

	want, err := tokencache.Key{
		Issuer:   tokenURL,
		Subject:  externalAudience,
		Scopes:   scopes,
		Audience: externalAudience,
	}.ID()
	if err != nil {
		t.Fatalf("ID: %v", err)
	}

	plain := lookedUp(t, "subject-a", "")
	if plain != want {
		t.Errorf("token looked up under %s, want %s", plain, want)
	}
	if got := lookedUp(t, "subject-b", ""); got != plain {
		t.Error("a different subject token changed the cache key")
	}
	if got := lookedUp(t, "subject-a", target); got == plain {
		t.Error("impersonating an account did not change the cache key")
	}
	if got := lookedUp(t, "subject-a", "", WithCredentialGeneration("job-1")); got == plain {
		t.Error("a credential generation did not change the cache key")
	}
}

// loadRecordingCache records the ids it is asked for.
type loadRecordingCache struct {
	*countingCache
	loads []string
}

func (c *loadRecordingCache) Load(id string) (*oauth2.Token, error) {
	c.loads = append(c.loads, id)

	return c.countingCache.Load(id)
}
