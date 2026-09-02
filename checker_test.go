package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestExpectedStatusCode(t *testing.T) {
	tests := []struct {
		name      string
		expect    string
		status    string
		want      string
		wantMatch bool
	}{
		{"matched", "HTTP/1.1 200,HTTP/2.0 200", "HTTP/2.0 200 OK", "HTTP/2.0 200", true},
		{"no match", "HTTP/1.1 200,HTTP/2.0 200", "HTTP/1.1 500 Internal Server Error", "", false},
		{"first match wins", "HTTP/,HTTP/2.0 200", "HTTP/2.0 200 OK", "HTTP/", true},
		// an empty pattern would match anything, so it must not be reported as a match
		{"leading comma", ",HTTP/1.1 200", "HTTP/1.1 200 OK", "HTTP/1.1 200", true},
		{"trailing comma", "HTTP/1.1 200,", "HTTP/1.1 500 Internal Server Error", "", false},
		// a list written with spaces is what a human types
		{"space after comma", "HTTP/1.1 200, HTTP/2.0 200", "HTTP/2.0 200 OK", "HTTP/2.0 200", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := Opt{Expect: tt.expect}
			got, ok := opt.ExpectedStatusCode(tt.status)
			if got != tt.want || ok != tt.wantMatch {
				t.Fatalf("ExpectedStatusCode(%q) = (%q, %v), want (%q, %v)", tt.status, got, ok, tt.want, tt.wantMatch)
			}
		})
	}
}

// BuildRequest tests
func TestBuildRequest(t *testing.T) {
	opt := Opt{
		Hostname:      "example.com",
		URI:           "/path",
		Method:        "POST",
		UserAgent:     "test-agent",
		Authorization: "user:pass",
		Port:          80,
	}

	ctx := context.Background()
	req, err := opt.BuildRequest(ctx)
	if err != nil {
		t.Fatalf("BuildRequest() error = %v", err)
	}

	if req.Method != "POST" {
		t.Fatalf("BuildRequest() Method = %q, want %q", req.Method, "POST")
	}

	if req.URL.String() != "http://example.com/path" {
		t.Fatalf("BuildRequest() URL = %q, want %q", req.URL.String(), "http://example.com/path")
	}

	if req.Header.Get("User-Agent") != "test-agent" {
		t.Fatalf("BuildRequest() User-Agent = %q, want %q", req.Header.Get("User-Agent"), "test-agent")
	}

	username, password, ok := req.BasicAuth()
	if !ok || username != "user" || password != "pass" {
		t.Fatalf("BuildRequest() BasicAuth = (%q, %q), want (%q, %q)", username, password, "user", "pass")
	}
}

// BuildRequestTest with SSL and SNI
func TestBuildRequestWithSSLAndSNI(t *testing.T) {
	opt := Opt{
		Hostname:  "example.com",
		URI:       "/path",
		Method:    "GET",
		UserAgent: "test-agent",
		SSL:       true,
		SNI:       true,
		Port:      443,
	}

	ctx := context.Background()
	req, err := opt.BuildRequest(ctx)
	if err != nil {
		t.Fatalf("BuildRequest() error = %v", err)
	}

	if req.URL.String() != "https://example.com/path" {
		t.Fatalf("BuildRequest() URL = %q, want %q", req.URL.String(), "https://example.com/path")
	}
}

// BuildRequestTest with invalid authorization
func TestBuildRequestWithInvalidAuthorization(t *testing.T) {
	opt := Opt{
		Hostname:      "example.com",
		URI:           "/path",
		Method:        "GET",
		UserAgent:     "test-agent",
		Authorization: "invalid-authorization",
	}

	ctx := context.Background()
	_, err := opt.BuildRequest(ctx)
	if err == nil {
		t.Fatalf("BuildRequest() error = nil, want non-nil")
	}
	if err.Error() != "invalid authorization args" {
		t.Fatalf("BuildRequest() error = %q, want %q", err.Error(), "invalid authorization args")
	}
}

func getTransport(opt *Opt) (*http.Transport, error) {
	tripper := opt.MakeTransport()
	if tripper == nil {
		return nil, fmt.Errorf("MakeTransport() returned nil")
	}
	transport, ok := tripper.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("MakeTransport() returned non-http.Transport")
	}
	return transport, nil
}

// a proxy cannot be reached through a dialer that ignores the address, so the
// transport must not be configured for one
func TestMakeTransportHasNoProxy(t *testing.T) {
	opt := Opt{SSL: true, Hostname: "example.com"}

	transport, err := getTransport(&opt)
	if err != nil {
		t.Fatalf("MakeTransport() error = %v", err)
	}
	if transport.Proxy != nil {
		t.Fatal("MakeTransport() Transport.Proxy is set, want nil")
	}
}

// MakeTransport tests with TLSMaxVersion
func TestMakeTransportWithTLSMaxVersion(t *testing.T) {
	{
		opt := Opt{
			SSL:           true,
			TLSMaxVersion: "1.2",
		}
		transport, err := getTransport(&opt)
		if err != nil {
			t.Fatalf("MakeTransport() error = %v", err)
		}
		if transport.TLSClientConfig.MaxVersion != tls.VersionTLS12 {
			t.Fatalf("MakeTransport() TLSClientConfig.MaxVersion = %d, want %d", transport.TLSClientConfig.MaxVersion, tls.VersionTLS12)
		}
	}
	{
		opt := Opt{
			SSL:           true,
			TLSMaxVersion: "1.3",
		}
		transport, err := getTransport(&opt)
		if err != nil {
			t.Fatalf("MakeTransport() error = %v", err)
		}
		if transport.TLSClientConfig.MaxVersion != tls.VersionTLS13 {
			t.Fatalf("MakeTransport() TLSClientConfig.MaxVersion = %d, want %d", transport.TLSClientConfig.MaxVersion, tls.VersionTLS13)
		}
	}
	{
		opt := Opt{
			SSL:           true,
			TLSMaxVersion: "1.1",
		}
		transport, err := getTransport(&opt)
		if err != nil {
			t.Fatalf("MakeTransport() error = %v", err)
		}
		if transport.TLSClientConfig.MaxVersion != tls.VersionTLS11 {
			t.Fatalf("MakeTransport() TLSClientConfig.MaxVersion = %d, want %d", transport.TLSClientConfig.MaxVersion, tls.VersionTLS11)
		}
		if transport.TLSClientConfig.MinVersion != tls.VersionTLS11 {
			t.Fatalf("MakeTransport() TLSClientConfig.MinVersion = %d, want %d", transport.TLSClientConfig.MinVersion, tls.VersionTLS11)
		}
	}
}

// MakeTransport tests with VerifySSL false
func TestMakeTransportWithVerifySSLFalse(t *testing.T) {
	opt := Opt{
		SSL: true,
	}

	transport, err := getTransport(&opt)
	if err != nil {
		t.Fatalf("MakeTransport() error = %v", err)
	}
	if transport.TLSClientConfig.InsecureSkipVerify != true {
		t.Fatalf("MakeTransport() TLSClientConfig.InsecureSkipVerify = %v, want %v", transport.TLSClientConfig.InsecureSkipVerify, true)
	}
}

// MakeTransport tests with VerifySSL true
func TestMakeTransportWithVerifySSLTrue(t *testing.T) {
	opt := Opt{
		SSL:       true,
		VerifySSL: true,
	}

	transport, err := getTransport(&opt)
	if err != nil {
		t.Fatalf("MakeTransport() error = %v", err)
	}
	if transport.TLSClientConfig.InsecureSkipVerify != false {
		t.Fatalf("MakeTransport() TLSClientConfig.InsecureSkipVerify = %v, want %v", transport.TLSClientConfig.InsecureSkipVerify, false)
	}
}

// MakeTransport tests with IgnoreSSLError true
func TestMakeTransportWithIgnoreSSLError(t *testing.T) {
	opt := Opt{
		SSL:            true,
		IgnoreSSLError: true,
	}

	transport, err := getTransport(&opt)
	if err != nil {
		t.Fatalf("MakeTransport() error = %v", err)
	}
	tlsConfig := transport.TLSClientConfig
	if tlsConfig.InsecureSkipVerify != true {
		t.Fatalf("MakeTransport() TLSClientConfig.InsecureSkipVerify = %v, want %v", tlsConfig.InsecureSkipVerify, true)
	}
	if tlsConfig.MinVersion != tls.VersionTLS10 {
		t.Fatalf("MakeTransport() TLSClientConfig.MinVersion = %d, want %d", tlsConfig.MinVersion, tls.VersionTLS10)
	}
	if len(tlsConfig.CipherSuites) != len(tls.CipherSuites())+len(tls.InsecureCipherSuites()) {
		t.Fatalf("MakeTransport() TLSClientConfig.CipherSuites = %d suites, want all %d", len(tlsConfig.CipherSuites), len(tls.CipherSuites())+len(tls.InsecureCipherSuites()))
	}
	for _, curve := range tlsConfig.CurvePreferences {
		if curve == tls.X25519MLKEM768 {
			t.Fatal("MakeTransport() TLSClientConfig.CurvePreferences contains X25519MLKEM768, want it disabled")
		}
	}
}

// IgnoreSSLError with an explicit --tls-max keeps the requested version window
func TestMakeTransportIgnoreSSLErrorWithTLSMaxVersion(t *testing.T) {
	opt := Opt{
		SSL:            true,
		IgnoreSSLError: true,
		TLSMaxVersion:  "1.1",
	}

	transport, err := getTransport(&opt)
	if err != nil {
		t.Fatalf("MakeTransport() error = %v", err)
	}
	if transport.TLSClientConfig.MaxVersion != tls.VersionTLS11 {
		t.Fatalf("MakeTransport() TLSClientConfig.MaxVersion = %d, want %d", transport.TLSClientConfig.MaxVersion, tls.VersionTLS11)
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS11 {
		t.Fatalf("MakeTransport() TLSClientConfig.MinVersion = %d, want %d", transport.TLSClientConfig.MinVersion, tls.VersionTLS11)
	}
}

func optForServer(t *testing.T, srv *httptest.Server) *Opt {
	t.Helper()
	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("Atoi() error = %v", err)
	}
	return &Opt{
		Hostname:  srv.Listener.Addr().String(),
		IPAddress: host,
		Port:      p,
		SSL:       true,
		Method:    "GET",
		URI:       "/",
		UserAgent: "check_http",
		Expect:    "HTTP/1.,HTTP/2.",
	}
}

// an untrusted certificate fails with --verify-ssl and is ignored with --ignore-ssl-error
func TestRequestSelfSignedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	opt := optForServer(t, srv)
	opt.VerifySSL = true
	if _, rErr := opt.Request(context.Background(), opt.BuildClient()); rErr == nil {
		t.Fatal("Request() error = nil, want certificate error")
	}

	opt = optForServer(t, srv)
	opt.IgnoreSSLError = true
	if _, rErr := opt.Request(context.Background(), opt.BuildClient()); rErr != nil {
		t.Fatalf("Request() error = %v, want nil", rErr)
	}
}

// a server that only speaks legacy TLS rejects the handshake unless --ignore-ssl-error is set
func TestRequestLegacyTLSServer(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS11,
	}
	srv.StartTLS()
	defer srv.Close()

	opt := optForServer(t, srv)
	if _, rErr := opt.Request(context.Background(), opt.BuildClient()); rErr == nil {
		t.Fatal("Request() error = nil, want handshake error")
	}

	opt = optForServer(t, srv)
	opt.IgnoreSSLError = true
	if _, rErr := opt.Request(context.Background(), opt.BuildClient()); rErr != nil {
		t.Fatalf("Request() error = %v, want nil", rErr)
	}
}

func serverOpt(t *testing.T, srv *httptest.Server, hostname string) *Opt {
	t.Helper()
	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("Atoi() error = %v", err)
	}
	return &Opt{
		Hostname:  hostname,
		IPAddress: host,
		Port:      p,
		Method:    "GET",
		URI:       "/",
		UserAgent: "check_http",
		Expect:    "HTTP/1.,HTTP/2.",
	}
}

// proxy environment variables must not reach the transport: they used to break
// https outright and silently un-proxy plain http
func TestRequestIgnoresProxyEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://192.0.2.1:3128")
	t.Setenv("HTTPS_PROXY", "http://192.0.2.1:3128")

	var gotRequestURI string
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRequestURI = r.RequestURI
	}))
	defer plain.Close()

	opt := serverOpt(t, plain, "example.com")
	if _, rErr := opt.Request(context.Background(), opt.BuildClient()); rErr != nil {
		t.Fatalf("Request() error = %v, want nil", rErr)
	}
	if gotRequestURI != "/" {
		t.Fatalf("request-target = %q, want %q (proxy form means the proxy config leaked in)", gotRequestURI, "/")
	}

	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer tlsSrv.Close()

	tlsOpt := serverOpt(t, tlsSrv, "example.com")
	tlsOpt.SSL = true
	if _, rErr := tlsOpt.Request(context.Background(), tlsOpt.BuildClient()); rErr != nil {
		t.Fatalf("Request() over https error = %v, want nil", rErr)
	}
}

// the Host header carries the port whenever it is not the scheme default
func TestRequestHost(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		port     int
		ssl      bool
		want     string
	}{
		{"default http port omitted", "example.com", 80, false, "example.com"},
		{"default https port omitted", "example.com", 443, true, "example.com"},
		{"custom port added", "example.com", 8443, true, "example.com:8443"},
		{"port already in hostname kept", "example.com:8080", 8080, false, "example.com:8080"},
		{"ipv6 literal bracketed", "::1", 80, false, "[::1]"},
		{"ipv6 literal with custom port", "::1", 8080, false, "[::1]:8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := Opt{Hostname: tt.hostname, Port: tt.port, SSL: tt.ssl, Method: "GET", URI: "/", UserAgent: "check_http"}
			if got := opt.requestHost(); got != tt.want {
				t.Fatalf("requestHost() = %q, want %q", got, tt.want)
			}

			req, err := opt.BuildRequest(context.Background())
			if err != nil {
				t.Fatalf("BuildRequest() error = %v", err)
			}
			if req.Host != "" && req.Host != tt.want {
				t.Fatalf("BuildRequest() Host = %q, want %q", req.Host, tt.want)
			}
			if req.URL.Host != tt.want {
				t.Fatalf("BuildRequest() URL.Host = %q, want %q", req.URL.Host, tt.want)
			}
		})
	}
}

// what the target actually receives
func TestRequestSendsHostHeaderWithPort(t *testing.T) {
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
	}))
	defer srv.Close()

	opt := serverOpt(t, srv, "example.com")
	if _, rErr := opt.Request(context.Background(), opt.BuildClient()); rErr != nil {
		t.Fatalf("Request() error = %v", rErr)
	}
	want := "example.com:" + strconv.Itoa(opt.Port)
	if gotHost != want {
		t.Fatalf("Host header = %q, want %q", gotHost, want)
	}
}

// SNI is sent for a hostname whether or not --sni was passed
func TestRequestAlwaysSendsSNI(t *testing.T) {
	for _, sni := range []bool{false, true} {
		var got string
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
		srv.TLS = &tls.Config{GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			got = chi.ServerName
			return nil, nil
		}}
		srv.StartTLS()

		opt := serverOpt(t, srv, "localhost")
		opt.SSL = true
		opt.SNI = sni
		if _, rErr := opt.Request(context.Background(), opt.BuildClient()); rErr != nil {
			t.Fatalf("Request() with sni=%v error = %v", sni, rErr)
		}
		srv.Close()

		if got != "localhost" {
			t.Fatalf("server saw SNI %q with sni=%v, want %q", got, sni, "localhost")
		}
	}
}

// the body is searched as it streams, so a match past max-buffer-size counts
func TestRequestMatchesBeyondBufferSize(t *testing.T) {
	body := append([]byte(strings.Repeat("a", 1000)), []byte("NEEDLE")...)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()

	opt := serverOpt(t, srv, "example.com")
	opt.ExpectContent = "NEEDLE"
	opt.MaxBufferSize = HumanBytes(50)
	if err := opt.verify(); err != nil {
		t.Fatalf("verify() error = %v", err)
	}

	msg, rErr := opt.Request(context.Background(), opt.BuildClient())
	if rErr != nil {
		t.Fatalf("Request() error = %v, want the match to be found beyond the cap", rErr)
	}
	if !strings.Contains(msg, "Response body matched") {
		t.Fatalf("Request() msg = %q, want it to report the body match", msg)
	}
}
