package grpc

import (
	"context"
	"os"

	"go.cbws.cloud/sdk/internal/perrpc"
	"go.cbws.cloud/sdk/internal/useragent"
	creds "go.cbws.cloud/sdk/oauth2"
	"go.cbws.cloud/sdk/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

// apiClient is the SDK's identification header for gRPC calls.
var apiClient = useragent.APIClient("grpc/" + grpc.Version)

type GRPCClient struct {
	client *grpc.ClientConn

	// quotaProject finds the project the client's calls are attributed to.
	// It returns "" when there is none. Nil means the same.
	quotaProject func(context.Context) string
}

func (g *GRPCClient) Invoke(ctx context.Context, method string, args interface{}, reply interface{}, opts ...grpc.CallOption) error {
	return g.client.Invoke(g.withHeaders(ctx), method, args, reply, opts...)
}

func (g *GRPCClient) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return g.client.NewStream(g.withHeaders(ctx), desc, method, opts...)
}

// withHeaders sets the headers the SDK sends on every outgoing call. They are
// set per call rather than at dial time so that they are also sent over a
// connection passed in with option.WithGRPCConn.
//
// The SDK's identification replaces any value the caller put in the context.
// The quota project is the other way round: a project the caller put in the
// context, with option.QuotaProjectContext, wins over the client's own. It is
// sent on every call rather than only on calls that name no project, because
// the service ignores it for a call that does, and a list of such calls kept
// here would miss every call a service adds later.
func (g *GRPCClient) withHeaders(ctx context.Context) context.Context {
	md, _ := metadata.FromOutgoingContext(ctx)
	md = md.Copy()
	md.Set(useragent.APIClientHeader, apiClient)

	if len(md.Get(option.QuotaProjectHeader)) == 0 && g.quotaProject != nil {
		if project := g.quotaProject(ctx); project != "" {
			md.Set(option.QuotaProjectHeader, project)
		}
	}

	return metadata.NewOutgoingContext(ctx, md)
}

func (g *GRPCClient) Close() error {
	return g.client.Close()
}

// transportCredentials secures the connection of a client that sends
// credentials, given the options the client was built with. It verifies the
// server against the system roots.
var transportCredentials = func([]option.ClientOption) credentials.TransportCredentials {
	return credentials.NewClientTLSFromCert(nil, "")
}

// New dials the endpoint the options name. The credentials it builds fetch
// tokens for as long as the client lives, so ending ctx does not end them:
// ctx may be a request's context even when the client outlives the request.
// Each call's own context bounds how long that call waits for a token.
func New(ctx context.Context, opts ...option.ClientOption) (*GRPCClient, error) {
	o, err := processAndValidateOpts(opts)
	if err != nil {
		return nil, err
	}

	var credentials *creds.Credentials
	if !o.NoAuth {
		credentials, err = clientCredentials(ctx, o)
		if err != nil {
			return nil, err
		}
		if credentials != nil {
			o.GRPCDialOpts = append(
				o.GRPCDialOpts,
				grpc.WithPerRPCCredentials(perrpc.New(credentials.TokenSource, true)),
				grpc.WithTransportCredentials(transportCredentials(opts)),
			)
		}
	}
	o.GRPCDialOpts = append(o.GRPCDialOpts, grpc.WithUserAgent(useragent.String(o.UserAgent)))

	if o.GRPCConn == nil {
		o.GRPCConn, err = grpc.Dial(o.Endpoint, o.GRPCDialOpts...)
		if err != nil {
			return nil, err
		}
	}

	return &GRPCClient{
		client:       o.GRPCConn,
		quotaProject: quotaProject(o, credentials),
	}, nil
}

// quotaProject returns how a client finds the project of its calls: the
// project it was built with, then the one in option.QuotaProjectEnvVar, then
// the metadata server's project when the credentials come from there. The
// metadata server is asked on the call's context, and a failure sends no
// project rather than failing the call. Credentials from anywhere else name
// no project the caller chose for its calls, so they give none.
func quotaProject(o *option.DialSettings, credentials *creds.Credentials) func(context.Context) string {
	project := o.QuotaProject
	if project == "" {
		project = os.Getenv(option.QuotaProjectEnvVar)
	}
	if project != "" {
		return func(context.Context) string { return project }
	}

	if credentials == nil || credentials.Kind() != creds.KindMetadata {
		return nil
	}

	return func(ctx context.Context) string {
		project, err := credentials.ProjectName(ctx)
		if err != nil {
			return ""
		}

		return project
	}
}

// clientCredentials builds the client's credentials on a context that keeps
// ctx's values but not its cancellation. Token sources hold the context they
// are built with and make every later token request on it, so a cancellation
// would fail every refresh once the first token expires.
func clientCredentials(ctx context.Context, o *option.DialSettings) (*creds.Credentials, error) {
	return o.Creds(context.WithoutCancel(ctx))
}

func processAndValidateOpts(opts []option.ClientOption) (*option.DialSettings, error) {
	var o option.DialSettings
	for _, opt := range opts {
		opt.Apply(&o)
	}
	if err := o.Validate(); err != nil {
		return nil, err
	}
	return &o, nil
}
