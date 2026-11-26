package externalaccount

import (
	"context"
	"crypto/tls"
	"fmt"

	"go.cbws.cloud/sdk/internal/perrpc"
	"go.cbws.cloud/sdk/internal/useragent"

	"go.cbws.cloud/api/iam/v1alpha1"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

// apiClient is the SDK's identification header for the call to IAM.
var apiClient = useragent.APIClient("grpc/" + grpc.Version)

// impersonationSource asks IAM for an access token of serviceAccount on
// every call, authenticated with an STS token exchanged for the purpose.
//
// It calls the generated IAM client rather than the SDK's, because the SDK's
// client finds its credentials through the package that uses this one.
//
// The STS token is not kept between calls. It is valid for minutes and
// needed once per impersonated token, so exchanging again each time costs
// one request an hour and reads the subject token afresh. For the same
// reason it connects for each token rather than holding a connection, which
// a token source has no Close to release.
type impersonationSource struct {
	ctx            context.Context
	iamEndpoint    string
	tlsConfig      *tls.Config
	serviceAccount string
	scopes         []string
	sts            oauth2.TokenSource
}

// Token returns a token of the impersonated account. An IAM refusal keeps
// the gRPC status IAM answered with, so status.Code reads it.
func (s impersonationSource) Token() (*oauth2.Token, error) {
	federated, err := s.sts.Token()
	if err != nil {
		return nil, err
	}

	// Without a configuration of its own, the server is verified against the
	// system roots. NewTLS copies the configuration, so the caller's is never
	// changed.
	transport := credentials.NewClientTLSFromCert(nil, "")
	if s.tlsConfig != nil {
		transport = credentials.NewTLS(s.tlsConfig)
	}

	conn, err := grpc.NewClient(s.iamEndpoint,
		grpc.WithTransportCredentials(transport),
		grpc.WithPerRPCCredentials(perrpc.New(oauth2.StaticTokenSource(federated), true)),
		grpc.WithUserAgent(useragent.String("")),
	)
	if err != nil {
		return nil, fmt.Errorf("externalaccount: could not connect to IAM: %w", err)
	}
	defer func() { _ = conn.Close() }()

	ctx := metadata.AppendToOutgoingContext(s.ctx, useragent.APIClientHeader, apiClient)
	response, err := v1alpha1.NewIAMServiceClient(conn).GenerateAccessToken(ctx, &v1alpha1.GenerateAccessTokenRequest{
		Name:  s.serviceAccount,
		Scope: s.scopes,
	})
	if err != nil {
		return nil, fmt.Errorf("externalaccount: IAM refused a token for %s: %w", s.serviceAccount, err)
	}

	// A token without an expiry reads as one that never expires to
	// golang.org/x/oauth2 and everything built on it, so one is refused
	// rather than handed on.
	if response.GetAccessToken() == "" || response.GetExpireTime() == nil {
		return nil, fmt.Errorf("externalaccount: IAM returned no access token or no expiry for %s", s.serviceAccount)
	}

	return &oauth2.Token{
		AccessToken: response.GetAccessToken(),
		TokenType:   "Bearer",
		Expiry:      response.GetExpireTime().AsTime(),
	}, nil
}
