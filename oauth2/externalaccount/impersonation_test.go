package externalaccount

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.cbws.cloud/api/iam/v1alpha1"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// iamServer is a fake IAM that mints a token for any account, or answers
// with the response or the error that respond returns.
type iamServer struct {
	v1alpha1.UnimplementedIAMServiceServer

	mu       sync.Mutex
	requests []iamRequest
	respond  func() (*v1alpha1.GenerateAccessTokenResponse, error)
}

type iamRequest struct {
	name          string
	authorization string
	scopes        []string
}

// iamEndpoint is where a fake IAM listens, and the TLS configuration that
// trusts it.
type iamEndpoint struct {
	address string
	tls     *tls.Config
}

// newIAM serves a fake IAM over TLS, with a certificate no public root signs.
func newIAM(t *testing.T) (*iamServer, iamEndpoint) {
	t.Helper()

	// httptest's certificate is valid for 127.0.0.1, which is where the
	// listener is.
	issuer := httptest.NewUnstartedServer(http.NotFoundHandler())
	issuer.StartTLS()
	certificates := issuer.TLS.Certificates
	roots := x509.NewCertPool()
	roots.AddCert(issuer.Certificate())
	issuer.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not listen: %v", err)
	}

	fake := &iamServer{}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: certificates})))
	v1alpha1.RegisterIAMServiceServer(server, fake)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	return fake, iamEndpoint{address: listener.Addr().String(), tls: &tls.Config{RootCAs: roots}}
}

func (s *iamServer) GenerateAccessToken(ctx context.Context, request *v1alpha1.GenerateAccessTokenRequest) (*v1alpha1.GenerateAccessTokenResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)

	s.mu.Lock()
	s.requests = append(s.requests, iamRequest{
		name:          request.GetName(),
		authorization: strings.Join(md.Get("authorization"), ","),
		scopes:        request.GetScope(),
	})
	issued, respond := len(s.requests), s.respond
	s.mu.Unlock()

	if respond != nil {
		return respond()
	}

	return &v1alpha1.GenerateAccessTokenResponse{
		AccessToken: fmt.Sprintf("sa-%d", issued),
		ExpireTime:  timestamppb.New(time.Now().Add(time.Hour)),
	}, nil
}

func (s *iamServer) received() []iamRequest {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]iamRequest(nil), s.requests...)
}

func impersonationConfig(sts *httptest.Server, iam iamEndpoint, path string) Config {
	conf := fileConfig(sts, path)
	conf.ServiceAccountImpersonation = testServiceAccount
	conf.IAMEndpoint = iam.address
	conf.IAMTLSConfig = iam.tls
	conf.Scopes = []string{"cbws.compute", "cbws.iam"}

	return conf
}

// TestImpersonation covers the second step: the STS token is presented to
// IAM, and the service account's token is what the caller gets.
func TestImpersonation(t *testing.T) {
	sts, stsServer := newSTS(t)
	iam, endpoint := newIAM(t)

	got, err := token(t, impersonationConfig(stsServer, endpoint, writeToken(t, "subject")))
	if err != nil {
		t.Fatalf("Token: %v", err)
	}

	if got.AccessToken != "sa-1" {
		t.Errorf("token = %q, want IAM's sa-1", got.AccessToken)
	}
	if remaining := time.Until(got.Expiry); remaining < 59*time.Minute {
		t.Errorf("token expires in %s, want IAM's hour", remaining)
	}
	if len(sts.received()) != 1 {
		t.Errorf("STS was called %d times, want once", len(sts.received()))
	}

	requests := iam.received()
	if len(requests) != 1 {
		t.Fatalf("IAM was called %d times, want once", len(requests))
	}
	want := iamRequest{
		name:          testServiceAccount,
		authorization: "Bearer sts-1",
		scopes:        []string{"cbws.compute", "cbws.iam"},
	}
	if fmt.Sprint(requests[0]) != fmt.Sprint(want) {
		t.Errorf("IAM got %+v, want %+v", requests[0], want)
	}
}

func TestImpersonationRefused(t *testing.T) {
	_, stsServer := newSTS(t)
	iam, endpoint := newIAM(t)
	iam.respond = func() (*v1alpha1.GenerateAccessTokenResponse, error) {
		return nil, status.Error(codes.PermissionDenied, "permission denied")
	}

	_, err := token(t, impersonationConfig(stsServer, endpoint, writeToken(t, "subject")))
	if err == nil {
		t.Fatal("Token succeeded")
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Errorf("status.Code = %s, want PermissionDenied", got)
	}
	if !strings.Contains(err.Error(), testServiceAccount) {
		t.Errorf("error does not name the account: %v", err)
	}
	if strings.Contains(err.Error(), "sts-1") {
		t.Errorf("error quotes the STS token: %v", err)
	}
}

func TestImpersonationWithoutExpiryIsRefused(t *testing.T) {
	_, stsServer := newSTS(t)
	iam, endpoint := newIAM(t)
	iam.respond = func() (*v1alpha1.GenerateAccessTokenResponse, error) {
		return &v1alpha1.GenerateAccessTokenResponse{AccessToken: "sa-forever"}, nil
	}

	if _, err := token(t, impersonationConfig(stsServer, endpoint, writeToken(t, "subject"))); err == nil {
		t.Fatal("Token accepted a token without an expiry")
	}
}

// TestImpersonationNeedsTransportSecurity covers an IAM that answers without
// TLS: the STS token is not sent to it.
func TestImpersonationNeedsTransportSecurity(t *testing.T) {
	_, stsServer := newSTS(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not listen: %v", err)
	}
	fake := &iamServer{}
	server := grpc.NewServer()
	v1alpha1.RegisterIAMServiceServer(server, fake)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	conf := impersonationConfig(stsServer, iamEndpoint{address: listener.Addr().String(), tls: &tls.Config{}}, writeToken(t, "subject"))
	if _, err := token(t, conf); err == nil {
		t.Fatal("Token succeeded over a connection without TLS")
	}
	if len(fake.received()) != 0 {
		t.Error("the STS token reached a server without TLS")
	}
}

// TestImpersonationVerifiesIAMByDefault covers a configuration without
// IAMTLSConfig: the system roots do not sign the fake's certificate, so the
// STS token is not sent to it.
func TestImpersonationVerifiesIAMByDefault(t *testing.T) {
	_, stsServer := newSTS(t)
	iam, endpoint := newIAM(t)

	conf := impersonationConfig(stsServer, endpoint, writeToken(t, "subject"))
	conf.IAMTLSConfig = nil

	if _, err := token(t, conf); err == nil {
		t.Fatal("Token succeeded against a server the system roots do not trust")
	}
	if len(iam.received()) != 0 {
		t.Error("the STS token reached an untrusted server")
	}
}

// TestImpersonationNeedsTheExchange covers an STS refusal before IAM: IAM is
// never asked, and the caller sees the STS error.
func TestImpersonationNeedsTheExchange(t *testing.T) {
	sts, stsServer := newSTS(t)
	sts.refuse = func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"error":"unauthorized_client"}`)
	}
	iam, endpoint := newIAM(t)

	_, err := token(t, impersonationConfig(stsServer, endpoint, writeToken(t, "subject")))

	var retrieve *oauth2.RetrieveError
	if !errors.As(err, &retrieve) || retrieve.ErrorCode != ErrorUnauthorizedClient {
		t.Fatalf("Token = %v, want unauthorized_client", err)
	}
	if len(iam.received()) != 0 {
		t.Error("IAM was called without an STS token")
	}
}
