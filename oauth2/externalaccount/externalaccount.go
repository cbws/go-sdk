// Package externalaccount obtains CBWS access tokens for a workload that runs
// outside CBWS, such as a GitLab CI job, without a service account key.
//
// The workload already holds a token from its own platform, the subject
// token. CBWS STS exchanges it, as RFC 8693 describes, for a short-lived
// token that names the workload. Only IAM accepts that token, so where the
// configuration names a service account to impersonate, IAM is asked for an
// ordinary access token for that account in a second step. Without one, the
// STS token is returned as it is, which is enough to call IAM and nothing
// else.
//
// A credential configuration file has the type external_account, and is
// found through CBWS_CREDENTIALS like a service account key:
//
//	{
//	  "type": "external_account",
//	  "audience": "projects/my-project/workloadIdentityPools/ci/providers/gitlab",
//	  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
//	  "service_account_impersonation": "projects/my-project/serviceAccounts/deploy@my-project.iam-sa.cbws.xyz",
//	  "credential_source": {"file": "/builds/.cbws-id-token"}
//	}
//
// The subject token is read again for every exchange, because the tokens of
// CI jobs and projected Kubernetes service accounts rotate. It is never
// logged, and neither is a token this package returns.
package externalaccount

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"regexp"

	"go.cbws.cloud/sdk/oauth2/refresh"

	"golang.org/x/oauth2"
)

const (
	// ConfigType is the type a credential configuration file of this package
	// declares.
	ConfigType = "external_account"

	// DefaultTokenURL is the STS endpoint subject tokens are exchanged at.
	DefaultTokenURL = "https://sts.cbws.cloud/v1alpha1/token"

	// DefaultIAMEndpoint is the gRPC endpoint of IAM, which mints the token
	// of an impersonated service account.
	DefaultIAMEndpoint = "dns:///iam.cbws.cloud:443"

	// TokenTypeJWT is the subject token type of a JWT, such as a GitLab CI ID
	// token or a projected Kubernetes service account token.
	TokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt"

	// TokenTypeIDToken is the subject token type of an OpenID Connect ID
	// token.
	TokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token"

	tokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
	grantTypeExchange    = "urn:ietf:params:oauth:grant-type:token-exchange"
)

// Config describes how a workload obtains its subject token and what it
// exchanges the token for. The JSON field names follow Google's external
// account configuration where the two mean the same thing.
type Config struct {
	// Type is ConfigType. It may be left empty in a Config built in code.
	Type string `json:"type,omitempty"`

	// Audience is the workload identity pool provider that verifies the
	// subject token, as
	// projects/{project}/workloadIdentityPools/{pool}/providers/{provider}.
	Audience string `json:"audience"`

	// SubjectTokenType is TokenTypeJWT or TokenTypeIDToken.
	SubjectTokenType string `json:"subject_token_type"`

	// TokenURL is the STS endpoint. Empty means DefaultTokenURL.
	TokenURL string `json:"token_url,omitempty"`

	// ServiceAccountImpersonation is the service account whose access token
	// is returned, as projects/{project}/serviceAccounts/{email}. IAM checks
	// the permission and the service enablement in the named project, so the
	// project is named rather than given as "-". Empty returns the STS token
	// itself, which only IAM accepts.
	ServiceAccountImpersonation string `json:"service_account_impersonation,omitempty"`

	// IAMEndpoint is the gRPC target IAM is called at, over TLS. Empty means
	// DefaultIAMEndpoint.
	IAMEndpoint string `json:"iam_endpoint,omitempty"`

	// IAMTLSConfig secures the connection to IAM, for a caller that has to
	// trust a server no public root signs, such as a stand-in in a test or a
	// lab. Nil verifies IAM against the system roots. The connection always
	// uses TLS: the STS token is never sent without it.
	IAMTLSConfig *tls.Config `json:"-"`

	// CredentialSource is where the subject token is read from. Exactly one
	// of it and SubjectTokenSupplier is set.
	CredentialSource *CredentialSource `json:"credential_source,omitempty"`

	// SubjectTokenSupplier supplies the subject token from code, for a
	// caller that obtains it in a way no CredentialSource describes.
	SubjectTokenSupplier SubjectTokenSupplier `json:"-"`

	// Scopes are the scopes requested for an impersonated account's token.
	// The STS token has no scopes, so they do not apply without
	// impersonation.
	Scopes []string `json:"-"`
}

// SubjectTokenSupplier returns the workload's current subject token. It is
// called for every exchange, so it returns a token that is valid now rather
// than one it kept from an earlier call.
type SubjectTokenSupplier interface {
	SubjectToken(ctx context.Context, options SupplierOptions) (string, error)
}

// SupplierOptions tells a SubjectTokenSupplier what the token is exchanged
// for, so one supplier can serve several configurations.
type SupplierOptions struct {
	Audience         string
	SubjectTokenType string
}

var (
	audiencePattern       = regexp.MustCompile(`^projects/([^/]+)/workloadIdentityPools/[^/]+/providers/[^/]+$`)
	serviceAccountPattern = regexp.MustCompile(`^projects/([^/?#]+)/serviceAccounts/[^/?#]+$`)
)

// ProjectName reports the project the credentials act in: the project of the
// impersonated service account where the configuration names one, and
// otherwise the project of the workload identity pool. It is empty for a
// configuration that is not valid.
func (c Config) ProjectName() string {
	if match := serviceAccountPattern.FindStringSubmatch(c.ServiceAccountImpersonation); match != nil && match[1] != "-" {
		return match[1]
	}
	if match := audiencePattern.FindStringSubmatch(c.Audience); match != nil {
		return match[1]
	}

	return ""
}

// NewTokenSource returns a source of access tokens for conf. The source
// reuses its token and fetches the replacement before it expires.
//
// Every fetch is made on ctx, so a source meant to outlive a request is built
// on a context without that request's cancellation. HTTP requests use the
// client in ctx under oauth2.HTTPClient, if there is one.
func NewTokenSource(ctx context.Context, conf Config) (oauth2.TokenSource, error) {
	if err := conf.validate(); err != nil {
		return nil, fmt.Errorf("externalaccount: %w", err)
	}

	supplier := conf.SubjectTokenSupplier
	if supplier == nil {
		var err error
		supplier, err = conf.CredentialSource.supplier(conf.ServiceAccountImpersonation)
		if err != nil {
			return nil, fmt.Errorf("externalaccount: %w", err)
		}
	}

	exchange := stsSource{
		ctx:              ctx,
		tokenURL:         cmp.Or(conf.TokenURL, DefaultTokenURL),
		audience:         conf.Audience,
		subjectTokenType: conf.SubjectTokenType,
		supplier:         supplier,
	}
	if conf.ServiceAccountImpersonation == "" {
		return refresh.NewTokenSource(exchange), nil
	}

	return refresh.NewTokenSource(impersonationSource{
		ctx:            ctx,
		iamEndpoint:    cmp.Or(conf.IAMEndpoint, DefaultIAMEndpoint),
		tlsConfig:      conf.IAMTLSConfig,
		serviceAccount: conf.ServiceAccountImpersonation,
		scopes:         conf.Scopes,
		sts:            exchange,
	}), nil
}

func (c Config) validate() error {
	if c.Type != "" && c.Type != ConfigType {
		return fmt.Errorf("configuration has type %q, expected %q", c.Type, ConfigType)
	}
	if !audiencePattern.MatchString(c.Audience) {
		return fmt.Errorf("audience %q is not a workload identity pool provider", c.Audience)
	}

	switch c.SubjectTokenType {
	case TokenTypeJWT, TokenTypeIDToken:
	default:
		return fmt.Errorf("subject_token_type %q is not supported, expected %q or %q", c.SubjectTokenType, TokenTypeJWT, TokenTypeIDToken)
	}

	if c.TokenURL != "" {
		if parsed, err := url.Parse(c.TokenURL); err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
			return fmt.Errorf("token_url %q is not an HTTP URL", c.TokenURL)
		}
	}

	if c.ServiceAccountImpersonation != "" && !serviceAccountPattern.MatchString(c.ServiceAccountImpersonation) {
		return fmt.Errorf("service_account_impersonation %q is not a service account name", c.ServiceAccountImpersonation)
	}

	switch {
	case c.CredentialSource == nil && c.SubjectTokenSupplier == nil:
		return errors.New("neither a credential_source nor a subject token supplier is set")
	case c.CredentialSource != nil && c.SubjectTokenSupplier != nil:
		return errors.New("both a credential_source and a subject token supplier are set")
	}

	return nil
}
