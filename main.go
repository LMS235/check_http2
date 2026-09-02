package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/jessevdk/go-flags"
)

var version string
var commit string

// versionSuffix marks builds of this fork, whatever the version comes from.
const versionSuffix = "-lms235"

const (
	OK = iota
	WARNING
	CRITICAL
	UNKNOWN
)

// cleanModuleVersion turns the module version recorded in the binary into a
// version worth displaying, or "" when it says no more than the revision does.
func cleanModuleVersion(moduleVersion, revision string) string {
	v := strings.TrimPrefix(moduleVersion, "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		// drop build metadata such as "+dirty" or "+incompatible"
		v = v[:i]
	}

	if v == "(devel)" {
		return ""
	}

	// For a build from a checkout the go tool derives a pseudo-version ending in
	// the revision, which is reported on its own anyway.
	if len(revision) >= 12 && strings.Contains(v, revision[:12]) {
		return ""
	}

	return v
}

// buildInfoVersion reports the version and revision the go tool recorded in the
// binary, which is what is available when building without the ldflags the
// Makefile passes.
func buildInfoVersion() (string, string) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", ""
	}

	var revision string
	var modified bool
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}

	v := cleanModuleVersion(info.Main.Version, revision)

	if len(revision) > 7 {
		revision = revision[:7]
	}
	if revision != "" && modified {
		revision += "-dirty"
	}

	return v, revision
}

// versionInfo returns the version and revision to display, preferring the values
// stamped in via ldflags and falling back to what the go tool embedded.
func versionInfo() (string, string) {
	v, c := version, commit
	if v == "" || c == "" {
		infoVersion, infoCommit := buildInfoVersion()
		if v == "" {
			v = infoVersion
		}
		if c == "" {
			c = infoCommit
		}
	}

	if v == "" {
		v = defaultVersion
	}
	if c == "" {
		c = "unknown"
	}

	return v + versionSuffix, c
}

func (opt *Opt) verifyWaitFor() error {
	if opt.WaitFor && opt.WaitForMax == 0 {
		return fmt.Errorf("wait-for-max is required when wait-for is enabled")
	}
	return nil
}

func (opt *Opt) verifyExpectedContent() error {
	if opt.ExpectContent != "" && opt.Base64ExpectContent != "" {
		return fmt.Errorf("both string and base64-string are specified")
	}

	if opt.ExpectContent != "" {
		opt.expectByte = []byte(opt.ExpectContent)
	}

	if opt.Base64ExpectContent != "" {
		data, err := base64.StdEncoding.DecodeString(opt.Base64ExpectContent)
		if err != nil {
			return fmt.Errorf("failed decode base64-string: %w", err)
		}
		opt.expectByte = data
	}

	return nil
}

func (opt *Opt) verifyExpect() error {
	if opt.Expect == "" {
		return nil
	}

	for e := range strings.SplitSeq(opt.Expect, ",") {
		if strings.TrimSpace(e) != "" {
			return nil
		}
	}

	return fmt.Errorf("expect holds no status to match: %q", opt.Expect)
}

// warn notes something the operator should know but that is not reason enough to
// refuse the check.
func (opt *Opt) warn(format string, args ...any) {
	opt.warnings = append(opt.warnings, fmt.Sprintf(format, args...))
}

// verifyAuthorization resolves the credentials, reading them from a file when
// one is given so they need not appear in the process list.
func (opt *Opt) verifyAuthorization() error {
	if opt.Authorization != "" && opt.AuthorizationFile != "" {
		return fmt.Errorf("both authorization and authorization-file are specified")
	}

	if opt.AuthorizationFile != "" {
		if err := opt.readAuthorizationFile(); err != nil {
			return err
		}
	}

	if opt.Authorization == "" {
		return nil
	}

	if !strings.Contains(opt.Authorization, ":") {
		return fmt.Errorf("invalid authorization args")
	}

	if !opt.SSL {
		opt.warn("sending basic authentication over plain http, credentials go out unencrypted: add -S")
	}

	return nil
}

func (opt *Opt) readAuthorizationFile() error {
	info, err := os.Stat(opt.AuthorizationFile)
	if err != nil {
		return fmt.Errorf("failed to read authorization-file: %w", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		opt.warn("authorization-file %s is accessible to more than its owner (mode %#o)", opt.AuthorizationFile, mode)
	}

	data, err := os.ReadFile(opt.AuthorizationFile)
	if err != nil {
		return fmt.Errorf("failed to read authorization-file: %w", err)
	}

	// The credentials are the first line; only the line ending is stripped, so a
	// password may hold spaces.
	line, _, _ := strings.Cut(string(data), "\n")
	opt.Authorization = strings.TrimRight(line, "\r")

	if opt.Authorization == "" {
		return fmt.Errorf("authorization-file %s holds no credentials", opt.AuthorizationFile)
	}

	return nil
}

func (opt *Opt) verifySSLOptions() error {
	if opt.VerifySSL && opt.IgnoreSSLError {
		return fmt.Errorf("both verify-ssl and ignore-ssl-error are specified")
	}
	return nil
}

func (opt *Opt) verifyHostOptions() error {
	if opt.TCP4 && opt.TCP6 {
		return fmt.Errorf("both tcp4 and tcp6 are specified")
	}

	if opt.SNI && opt.Hostname == "" {
		return fmt.Errorf("hostname is required when using sni")
	}

	if opt.Hostname == "" && opt.IPAddress == "" {
		return fmt.Errorf("specify either hostname or ipaddress")
	}

	return nil
}

func (opt *Opt) normalizeHostAndIP() {
	if opt.Hostname == "" {
		opt.Hostname = opt.IPAddress
	}

	if opt.IPAddress == "" {
		host, _, err := net.SplitHostPort(opt.Hostname)
		if err != nil {
			opt.IPAddress = opt.Hostname
			return
		}
		opt.IPAddress = host
	}
}

// defaultPort is the port for the scheme when none was given.
func defaultPort(ssl bool) int {
	if ssl {
		return 443
	}
	return 80
}

func (opt *Opt) setDefaultPort() error {
	if opt.Port == 0 {
		if _, port, err := net.SplitHostPort(opt.Hostname); err == nil {
			p, err := strconv.Atoi(port)
			if err != nil {
				return fmt.Errorf("invalid port %q in hostname %q", port, opt.Hostname)
			}
			opt.Port = p
		}
	}

	if opt.Port == 0 {
		opt.Port = defaultPort(opt.SSL)
	}

	if opt.Port < 1 || opt.Port > 65535 {
		return fmt.Errorf("port %d is out of range", opt.Port)
	}

	return nil
}

func (opt *Opt) setDefaultURI() {
	if opt.URI == "" {
		opt.URI = "/"
	}
}

func (opt *Opt) verify() error {
	opt.bufferSize = uint64(opt.MaxBufferSize)

	if err := opt.verifyWaitFor(); err != nil {
		return err
	}

	if err := opt.verifyExpectedContent(); err != nil {
		return err
	}

	if err := opt.verifyExpect(); err != nil {
		return err
	}

	if err := opt.verifySSLOptions(); err != nil {
		return err
	}

	if err := opt.verifyAuthorization(); err != nil {
		return err
	}

	if err := opt.verifyHostOptions(); err != nil {
		return err
	}

	opt.normalizeHostAndIP()

	if err := opt.setDefaultPort(); err != nil {
		return err
	}

	opt.setDefaultURI()

	return nil
}

func (opt *Opt) BuildClient() *http.Client {
	transport := opt.MakeTransport()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: opt.Timeout,
	}
	return client
}

// runTimeout is the deadline for the whole run: every request it is asked to
// make plus the interim waits between them, and the slack the single-request
// case has always had.
func (opt *Opt) runTimeout() time.Duration {
	if opt.WaitForMax > 0 {
		return opt.WaitForMax
	}

	requests := max(opt.Consecutive, 1)

	const slack = 3 * time.Second
	total := slack + time.Duration(requests)*opt.Timeout + time.Duration(requests-1)*opt.Interim
	if total < slack {
		// an absurd --consecutive overflowed the duration; no deadline is a
		// better answer than one that has already passed
		return math.MaxInt64
	}

	return total
}

func (opt *Opt) run() int {
	client := opt.BuildClient()

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, opt.runTimeout())
	defer cancel()

	if opt.WaitFor {
		msg, code := opt.runWaitFor(ctx, client)
		fmt.Println(msg)
		return code
	}

	msg, code := opt.runRequest(ctx, client)
	fmt.Println(msg)
	return code
}

func main() {
	os.Exit(_main())
}

func _main() int {
	opt := &Opt{}
	psr := flags.NewParser(opt, flags.HelpFlag|flags.PassDoubleDash)
	_, err := psr.Parse()
	if opt.Version {
		v, c := versionInfo()
		fmt.Printf(
			"%s-%s\n%s/%s, %s, %s\n",
			filepath.Base(os.Args[0]),
			v,
			runtime.GOOS,
			runtime.GOARCH,
			runtime.Version(),
			c)
		return OK
	} else if flags.WroteHelp(err) {
		fmt.Fprintf(os.Stdout, "%v\n", err)
		return OK
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return UNKNOWN
	}
	if err := opt.verify(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return UNKNOWN
	}
	for _, w := range opt.warnings {
		log.Printf("warning: %s", w)
	}
	return opt.run()
}
