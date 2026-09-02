package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestVerifyBufferSize(t *testing.T) {
	opt := Opt{Hostname: "example.com", MaxBufferSize: HumanBytes(2048)}
	if err := opt.verify(); err != nil {
		t.Fatalf("verify() error = %v", err)
	}
	if opt.bufferSize != 2048 {
		t.Fatalf("bufferSize = %d, want 2048", opt.bufferSize)
	}
}

func TestVerifyWaitForWithoutMax(t *testing.T) {
	opt := Opt{WaitFor: true, Hostname: "example.com"}
	if err := opt.verify(); err == nil {
		t.Fatal("verify() error = nil, want error")
	}
}

func TestVerifyExpectContentSetsExpectByte(t *testing.T) {
	opt := Opt{Hostname: "example.com", ExpectContent: "hello"}
	if err := opt.verify(); err != nil {
		t.Fatalf("verify() error = %v", err)
	}
	if string(opt.expectByte) != "hello" {
		t.Fatalf("expectByte = %q, want %q", opt.expectByte, "hello")
	}
}

func TestVerifyBase64ExpectContent(t *testing.T) {
	opt := Opt{Hostname: "example.com", Base64ExpectContent: "aGVsbG8="}
	if err := opt.verify(); err != nil {
		t.Fatalf("verify() error = %v", err)
	}
	if string(opt.expectByte) != "hello" {
		t.Fatalf("expectByte = %q, want %q", opt.expectByte, "hello")
	}
}

func TestVerifyBase64ExpectContentInvalid(t *testing.T) {
	opt := Opt{Hostname: "example.com", Base64ExpectContent: "!!!"}
	if err := opt.verify(); err == nil {
		t.Fatal("verify() error = nil, want error")
	}
}

func TestVerifyBothExpectContents(t *testing.T) {
	opt := Opt{Hostname: "example.com", ExpectContent: "plain", Base64ExpectContent: "aGVsbG8="}
	if err := opt.verify(); err == nil {
		t.Fatal("verify() error = nil, want error")
	}
}

func TestVerifyBothTCPModes(t *testing.T) {
	opt := Opt{Hostname: "example.com", TCP4: true, TCP6: true}
	if err := opt.verify(); err == nil {
		t.Fatal("verify() error = nil, want error")
	}
}

func TestVerifySNIRequiresHostname(t *testing.T) {
	opt := Opt{SNI: true, IPAddress: "127.0.0.1"}
	if err := opt.verify(); err == nil {
		t.Fatal("verify() error = nil, want error")
	}
}

func TestVerifyNoHost(t *testing.T) {
	opt := Opt{}
	if err := opt.verify(); err == nil {
		t.Fatal("verify() error = nil, want error")
	}
}

func TestVerifyDefaults(t *testing.T) {
	opt := Opt{Hostname: "example.com"}
	if err := opt.verify(); err != nil {
		t.Fatalf("verify() error = %v", err)
	}
	if opt.URI != "/" {
		t.Fatalf("URI = %q, want %q", opt.URI, "/")
	}
	if opt.Port != 80 {
		t.Fatalf("Port = %d, want 80", opt.Port)
	}
	if opt.IPAddress != "example.com" {
		t.Fatalf("IPAddress = %q, want %q", opt.IPAddress, "example.com")
	}
}

func TestVerifyDefaultPortFromHostname(t *testing.T) {
	opt := Opt{Hostname: "example.com:8080"}
	if err := opt.verify(); err != nil {
		t.Fatalf("verify() error = %v", err)
	}
	if opt.Port != 8080 {
		t.Fatalf("Port = %d, want 8080", opt.Port)
	}
	if opt.IPAddress != "example.com" {
		t.Fatalf("IPAddress = %q, want %q", opt.IPAddress, "example.com")
	}
}

func TestVerifySSLDefaultPort(t *testing.T) {
	opt := Opt{Hostname: "example.com", SSL: true}
	if err := opt.verify(); err != nil {
		t.Fatalf("verify() error = %v", err)
	}
	if opt.Port != 443 {
		t.Fatalf("Port = %d, want 443", opt.Port)
	}
}

func TestVerifyExplicitPortOverridesDefault(t *testing.T) {
	opt := Opt{Hostname: "example.com:8443", Port: 9443, SSL: true}
	if err := opt.verify(); err != nil {
		t.Fatalf("verify() error = %v", err)
	}
	if opt.Port != 9443 {
		t.Fatalf("Port = %d, want 9443", opt.Port)
	}
}

func TestVerifyIPAddressFallback(t *testing.T) {
	opt := Opt{IPAddress: "192.0.2.1"}
	if err := opt.verify(); err != nil {
		t.Fatalf("verify() error = %v", err)
	}
	if opt.Hostname != "192.0.2.1" {
		t.Fatalf("Hostname = %q, want %q", opt.Hostname, "192.0.2.1")
	}
}

func TestVerifyBothSSLVerifyModes(t *testing.T) {
	opt := Opt{Hostname: "example.com", SSL: true, VerifySSL: true, IgnoreSSLError: true}
	if err := opt.verify(); err == nil {
		t.Fatal("verify() error = nil, want error")
	}
}

func TestVerifyIgnoreSSLError(t *testing.T) {
	opt := Opt{Hostname: "example.com", SSL: true, IgnoreSSLError: true}
	if err := opt.verify(); err != nil {
		t.Fatalf("verify() error = %v", err)
	}
}

func TestCleanModuleVersion(t *testing.T) {
	tests := []struct {
		name          string
		moduleVersion string
		revision      string
		want          string
	}{
		{"released version", "v0.0.25", "", "0.0.25"},
		{"prerelease version", "v1.0.0-rc1", "", "1.0.0-rc1"},
		{"build metadata dropped", "v0.0.25+incompatible", "", "0.0.25"},
		{"devel", "(devel)", "8cb1db2901f17b704945fa8f3de7ebfe37d3d8ad", ""},
		{"pseudo version", "v0.0.0-20260902164506-8cb1db2901f1+dirty", "8cb1db2901f17b704945fa8f3de7ebfe37d3d8ad", ""},
		{"empty", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cleanModuleVersion(tt.moduleVersion, tt.revision); got != tt.want {
				t.Fatalf("cleanModuleVersion(%q, %q) = %q, want %q", tt.moduleVersion, tt.revision, got, tt.want)
			}
		})
	}
}

func TestVersionInfoFromLDFlags(t *testing.T) {
	setVersionGlobals(t, "0.0.25", "abcdef1")

	v, c := versionInfo()
	if v != "0.0.25"+versionSuffix {
		t.Fatalf("versionInfo() version = %q, want %q", v, "0.0.25"+versionSuffix)
	}
	if c != "abcdef1" {
		t.Fatalf("versionInfo() commit = %q, want %q", c, "abcdef1")
	}
}

// without ldflags the output must still be readable, never an empty version
func TestVersionInfoWithoutLDFlags(t *testing.T) {
	setVersionGlobals(t, "", "")

	v, c := versionInfo()
	if v != defaultVersion+versionSuffix {
		t.Fatalf("versionInfo() version = %q, want %q", v, defaultVersion+versionSuffix)
	}
	if !strings.HasSuffix(v, versionSuffix) {
		t.Fatalf("versionInfo() version = %q, want suffix %q", v, versionSuffix)
	}
	if c == "" {
		t.Fatal("versionInfo() commit is empty, want a placeholder")
	}
}

func setVersionGlobals(t *testing.T, v, c string) {
	t.Helper()
	origVersion, origCommit := version, commit
	t.Cleanup(func() {
		version, commit = origVersion, origCommit
	})
	version, commit = v, c
}

// the deadline has to cover every request the run is configured to make
func TestRunTimeout(t *testing.T) {
	tests := []struct {
		name string
		opt  Opt
		want time.Duration
	}{
		{"single request", Opt{Timeout: 10 * time.Second, Consecutive: 1, Interim: time.Second}, 13 * time.Second},
		{"consecutive requests", Opt{Timeout: 10 * time.Second, Consecutive: 3, Interim: time.Second}, 35 * time.Second},
		{"consecutive unset", Opt{Timeout: 10 * time.Second, Interim: time.Second}, 13 * time.Second},
		{"wait-for-max wins", Opt{Timeout: 10 * time.Second, Consecutive: 3, Interim: time.Second, WaitForMax: 20 * time.Second}, 20 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.opt.runTimeout(); got != tt.want {
				t.Fatalf("runTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

// a run of consecutive successes must not be cut off by the deadline
func TestRunConsecutiveSucceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("Atoi() error = %v", err)
	}

	opt := Opt{
		Hostname: "example.com", IPAddress: host, Port: p,
		Method: "GET", URI: "/", UserAgent: "check_http", Expect: "HTTP/1.,HTTP/2.",
		Timeout: time.Second, Consecutive: 4, Interim: 300 * time.Millisecond,
	}
	if err := opt.verify(); err != nil {
		t.Fatalf("verify() error = %v", err)
	}

	if code := opt.run(); code != OK {
		t.Fatalf("run() = %d, want %d (every request succeeded)", code, OK)
	}
}

func TestVerifyPort(t *testing.T) {
	tests := []struct {
		name     string
		opt      Opt
		wantErr  bool
		wantPort int
	}{
		{"port from hostname", Opt{Hostname: "example.com:8080"}, false, 8080},
		{"non-numeric port in hostname", Opt{Hostname: "example.com:http"}, true, 0},
		{"port out of range in hostname", Opt{Hostname: "example.com:99999"}, true, 0},
		{"explicit port out of range", Opt{Hostname: "example.com", Port: 70000}, true, 0},
		{"explicit negative port", Opt{Hostname: "example.com", Port: -1}, true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opt.verify()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("verify() error = nil, want error (port resolved to %d)", tt.opt.Port)
				}
				return
			}
			if err != nil {
				t.Fatalf("verify() error = %v", err)
			}
			if tt.opt.Port != tt.wantPort {
				t.Fatalf("Port = %d, want %d", tt.opt.Port, tt.wantPort)
			}
		})
	}
}

func TestVerifyExpect(t *testing.T) {
	tests := []struct {
		name    string
		expect  string
		wantErr bool
	}{
		{"empty disables the check", "", false},
		{"normal list", "HTTP/1.,HTTP/2.", false},
		{"list with spaces", "HTTP/1.1 200, HTTP/2.0 200", false},
		{"only separators", ",", true},
		{"only whitespace", " , ", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := Opt{Hostname: "example.com", Expect: tt.expect}
			err := opt.verify()
			if tt.wantErr != (err != nil) {
				t.Fatalf("verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// an absurd --consecutive must not wrap the deadline into the past
func TestRunTimeoutDoesNotOverflow(t *testing.T) {
	opt := Opt{Timeout: 10 * time.Second, Interim: time.Second, Consecutive: 1 << 40}
	if got := opt.runTimeout(); got <= 0 {
		t.Fatalf("runTimeout() = %v, want a positive duration", got)
	}
}
