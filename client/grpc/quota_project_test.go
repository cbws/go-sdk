package grpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	creds "go.cbws.cloud/sdk/oauth2"
	"go.cbws.cloud/sdk/option"
	"google.golang.org/grpc/metadata"
)

func TestQuotaProject(t *testing.T) {
	tests := []struct {
		name string
		env  string
		opts []option.ClientOption
		ctx  func(context.Context) context.Context
		want []string
	}{
		{name: "no project sends none"},
		{
			name: "client option",
			opts: []option.ClientOption{option.WithQuotaProject("client-project")},
			want: []string{"client-project"},
		},
		{
			name: "environment variable",
			env:  "env-project",
			want: []string{"env-project"},
		},
		{
			name: "client option wins over the environment",
			env:  "env-project",
			opts: []option.ClientOption{option.WithQuotaProject("client-project")},
			want: []string{"client-project"},
		},
		{
			name: "per-call override wins over the client",
			env:  "env-project",
			opts: []option.ClientOption{option.WithQuotaProject("client-project")},
			ctx: func(ctx context.Context) context.Context {
				return option.QuotaProjectContext(ctx, "call-project")
			},
			want: []string{"call-project"},
		},
		{
			name: "per-call override without a client project",
			ctx: func(ctx context.Context) context.Context {
				return option.QuotaProjectContext(ctx, "call-project")
			},
			want: []string{"call-project"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(option.QuotaProjectEnvVar, tt.env)
			opts, received := serve(t)

			ctx := context.Background()
			if tt.ctx != nil {
				ctx = tt.ctx(ctx)
			}
			check(t, ctx, append(opts, tt.opts...)...)

			assert.Equal(t, tt.want, received.Get(option.QuotaProjectHeader))
		})
	}
}

func TestQuotaProjectOnAProvidedConnection(t *testing.T) {
	t.Setenv(option.QuotaProjectEnvVar, "")
	opts, received := serve(t)

	dialled, err := New(context.Background(), opts...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = dialled.Close() })

	check(t, context.Background(),
		option.WithGRPCConn(dialled.client),
		option.WithoutAuthentication(),
		option.WithQuotaProject("client-project"),
	)

	assert.Equal(t, []string{"client-project"}, received.Get(option.QuotaProjectHeader))
}

// TestQuotaProjectIgnoresTheKeysProject checks that a service account key
// does not attribute calls to the project it was issued in: the key says who
// the caller is, not which project the caller wants its calls charged to.
func TestQuotaProjectIgnoresTheKeysProject(t *testing.T) {
	t.Setenv(option.QuotaProjectEnvVar, "")

	credentials, err := creds.NewFromJSON(context.Background(), serviceAccountKey(t), nil)
	require.NoError(t, err)
	require.Equal(t, creds.KindServiceAccountKey, credentials.Kind())

	o, err := processAndValidateOpts(nil)
	require.NoError(t, err)

	assert.Nil(t, quotaProject(o, credentials))
}

func TestQuotaProjectIsNotDuplicated(t *testing.T) {
	client := &GRPCClient{quotaProject: func(context.Context) string { return "client-project" }}

	ctx := client.withHeaders(option.QuotaProjectContext(context.Background(), "call-project"))

	md, _ := metadata.FromOutgoingContext(ctx)
	assert.Equal(t, []string{"call-project"}, md.Get(option.QuotaProjectHeader))
}
