package v1alpha1_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	projects "go.cbws.cloud/sdk/cbws/projects/v1alpha1"
	"go.cbws.cloud/sdk/oauth2"
	"go.cbws.cloud/sdk/option"
)

// liveProjectEnvVar names the project the live test reads. It is set only
// where the environment also supplies credentials for the platform, such as
// the public repository's workflow. Everywhere else the test skips, so the
// unit test run never reaches the network.
const liveProjectEnvVar = "CBWS_SDK_LIVE_PROJECT"

// TestLiveGetProject reads a project from the live platform with the
// credentials the environment supplies. One call covers the whole chain:
// finding the credentials, exchanging them for an access token, and an
// authorized gRPC call that the platform accepts.
func TestLiveGetProject(t *testing.T) {
	project := os.Getenv(liveProjectEnvVar)
	if project == "" {
		t.Skipf("%s is not set", liveProjectEnvVar)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	creds, err := oauth2.FindDefaultCredentials(ctx)
	require.NoError(t, err)

	// The credentials know their own project, and the workflow points them at
	// the project it reads, so a mismatch means the wrong credentials were
	// found before any call is made.
	name, err := creds.ProjectName(ctx)
	require.NoError(t, err)
	require.Equal(t, project, name)

	client, err := projects.NewClient(ctx, option.WithCredentials(creds))
	require.NoError(t, err)

	got, err := client.GetProject(ctx, project)
	require.NoError(t, err)
	require.Equal(t, "projects/"+project, got.GetName())
}
