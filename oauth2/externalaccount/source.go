package externalaccount

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"go.cbws.cloud/sdk/internal/useragent"

	"golang.org/x/oauth2"
)

// AllowExecutablesEnvVar must be set to 1 before a configuration may run an
// executable for its subject token.
//
// A credential configuration is found through an environment variable, and
// whoever can point that variable at a file of their own would otherwise
// choose a command for this process to run. Setting this variable is the
// process owner's statement that running one is intended.
const AllowExecutablesEnvVar = "CBWS_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES"

const (
	defaultExecutableTimeout = 30 * time.Second
	minimumExecutableTimeout = 5 * time.Second
	maximumExecutableTimeout = 120 * time.Second

	// maximumTokenSize bounds what is read from a file, a URL or an
	// executable. A subject token is a few kilobytes at most, and the bound
	// keeps a misconfigured source from filling memory.
	maximumTokenSize = 1 << 20
)

// CredentialSource is where the subject token is read from. Exactly one of
// File, URL and Executable is set.
type CredentialSource struct {
	// File is a path the token is read from, such as the projected service
	// account token of a Kubernetes pod.
	File string `json:"file,omitempty"`

	// URL is fetched with a GET request and Headers for the token.
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`

	// Executable is run for the token, which it writes to its standard
	// output. It runs only where AllowExecutablesEnvVar is set to 1.
	Executable *ExecutableConfig `json:"executable,omitempty"`

	// Format is how the token is read out of what the source returns.
	// Without one, the whole of it is the token.
	Format *Format `json:"format,omitempty"`
}

// ExecutableConfig is a command that prints the subject token.
//
// Command is split on white space and run without a shell, so it cannot hold
// quoting, pipes or variable expansion. The command sees the environment of
// this process, plus CBWS_EXTERNAL_ACCOUNT_AUDIENCE and
// CBWS_EXTERNAL_ACCOUNT_TOKEN_TYPE, and CBWS_EXTERNAL_ACCOUNT_IMPERSONATED_ACCOUNT
// where the configuration names one. What it writes to its standard error is
// discarded.
type ExecutableConfig struct {
	Command string `json:"command"`

	// TimeoutMillis bounds how long the command may run, from 5 to 120
	// seconds. Without one, it is 30 seconds.
	TimeoutMillis *int `json:"timeout_millis,omitempty"`
}

// Format is how the subject token is read out of what a source returns.
type Format struct {
	// Type is "text", where the whole response is the token, or "json",
	// where the response is a JSON object and the token is the string in
	// SubjectTokenFieldName. Empty means "text".
	Type string `json:"type,omitempty"`

	SubjectTokenFieldName string `json:"subject_token_field_name,omitempty"`
}

// supplier returns the supplier that reads the token from s. impersonated is
// the account the configuration impersonates, if any, which an executable is
// told about.
func (s *CredentialSource) supplier(impersonated string) (SubjectTokenSupplier, error) {
	set := 0
	for _, present := range []bool{s.File != "", s.URL != "", s.Executable != nil} {
		if present {
			set++
		}
	}
	if set != 1 {
		return nil, errors.New("credential_source must set exactly one of file, url and executable")
	}

	if err := s.Format.validate(); err != nil {
		return nil, err
	}

	switch {
	case s.File != "":
		return fileSupplier{path: s.File, format: s.Format}, nil

	case s.URL != "":
		return urlSupplier{url: s.URL, headers: s.Headers, format: s.Format}, nil

	default:
		return s.Executable.supplier(s.Format, impersonated)
	}
}

func (f *Format) validate() error {
	if f == nil {
		return nil
	}

	switch f.Type {
	case "", "text":
		return nil

	case "json":
		if f.SubjectTokenFieldName == "" {
			return errors.New("credential_source format json needs a subject_token_field_name")
		}

		return nil

	default:
		return fmt.Errorf("credential_source format type %q is not supported, expected text or json", f.Type)
	}
}

// parse reads the subject token out of raw. No error it returns quotes raw,
// which is or holds the token.
func (f *Format) parse(raw []byte) (string, error) {
	var token string
	if f == nil || f.Type != "json" {
		token = strings.TrimSpace(string(raw))
	} else {
		var fields map[string]any
		if err := json.Unmarshal(raw, &fields); err != nil {
			return "", errors.New("the subject token source did not return a JSON object")
		}

		value, ok := fields[f.SubjectTokenFieldName].(string)
		if !ok {
			return "", fmt.Errorf("the subject token source returned no string in %q", f.SubjectTokenFieldName)
		}
		token = strings.TrimSpace(value)
	}

	if token == "" {
		return "", errors.New("the subject token source returned an empty token")
	}

	return token, nil
}

type fileSupplier struct {
	path   string
	format *Format
}

func (s fileSupplier) SubjectToken(context.Context, SupplierOptions) (string, error) {
	file, err := os.Open(s.path)
	if err != nil {
		return "", fmt.Errorf("could not read the subject token: %w", err)
	}
	defer func() { _ = file.Close() }()

	raw, err := io.ReadAll(io.LimitReader(file, maximumTokenSize))
	if err != nil {
		return "", fmt.Errorf("could not read the subject token from %s: %w", s.path, err)
	}

	return s.format.parse(raw)
}

type urlSupplier struct {
	url     string
	headers map[string]string
	format  *Format
}

func (s urlSupplier) SubjectToken(ctx context.Context, _ SupplierOptions) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return "", fmt.Errorf("could not request the subject token: %w", err)
	}
	for name, value := range s.headers {
		req.Header.Set(name, value)
	}

	resp, err := oauth2.NewClient(useragent.Context(ctx), nil).Do(req)
	if err != nil {
		return "", fmt.Errorf("could not request the subject token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maximumTokenSize))
	if err != nil {
		return "", fmt.Errorf("could not read the subject token from %s: %w", s.url, err)
	}
	// The body is not quoted: a source that answers with an error page may
	// still have put a token in it.
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("the subject token URL %s answered %s", s.url, resp.Status)
	}

	return s.format.parse(raw)
}

func (e *ExecutableConfig) supplier(format *Format, impersonated string) (SubjectTokenSupplier, error) {
	if os.Getenv(AllowExecutablesEnvVar) != "1" {
		return nil, fmt.Errorf("credential_source runs an executable, which needs %s=1 in the environment", AllowExecutablesEnvVar)
	}

	args := strings.Fields(e.Command)
	if len(args) == 0 {
		return nil, errors.New("credential_source executable has no command")
	}

	timeout := defaultExecutableTimeout
	if e.TimeoutMillis != nil {
		timeout = time.Duration(*e.TimeoutMillis) * time.Millisecond
		if timeout < minimumExecutableTimeout || timeout > maximumExecutableTimeout {
			return nil, fmt.Errorf("credential_source executable timeout_millis must be from %d to %d", minimumExecutableTimeout.Milliseconds(), maximumExecutableTimeout.Milliseconds())
		}
	}

	return executableSupplier{args: args, timeout: timeout, format: format, impersonated: impersonated}, nil
}

type executableSupplier struct {
	args    []string
	timeout time.Duration
	format  *Format

	// impersonated is the account the configuration impersonates, which
	// the command is told about.
	impersonated string
}

func (s executableSupplier) SubjectToken(ctx context.Context, options SupplierOptions) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.args[0], s.args[1:]...)
	cmd.Env = append(os.Environ(),
		"CBWS_EXTERNAL_ACCOUNT_AUDIENCE="+options.Audience,
		"CBWS_EXTERNAL_ACCOUNT_TOKEN_TYPE="+options.SubjectTokenType,
	)
	if s.impersonated != "" {
		cmd.Env = append(cmd.Env, "CBWS_EXTERNAL_ACCOUNT_IMPERSONATED_ACCOUNT="+s.impersonated)
	}

	// Standard error is discarded rather than kept on the error, where a
	// caller that logs the error would log whatever the command printed.
	var stdout bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, n: maximumTokenSize}
	cmd.Stderr = io.Discard
	// A child the command leaves behind may hold its output open; without
	// this, waiting for that output outlasts the timeout.
	cmd.WaitDelay = time.Second

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("the subject token executable %s did not finish within %s", s.args[0], s.timeout)
		}

		return "", fmt.Errorf("the subject token executable %s failed: %w", s.args[0], err)
	}

	return s.format.parse(stdout.Bytes())
}

// limitedWriter keeps the first n bytes written to it and drops the rest, so
// that a command printing without end cannot fill memory.
type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}

	kept := p[:min(len(p), l.n)]
	l.n -= len(kept)
	if _, err := l.w.Write(kept); err != nil {
		return 0, err
	}

	return len(p), nil
}
