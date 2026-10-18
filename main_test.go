package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// parseSSHKeygenDuration — duration parser
// -----------------------------------------------------------------------------

func TestParseSSHKeygenDuration(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		err  bool
	}{
		// ssh-keygen / time.ParseDuration units
		{"8h", 8 * time.Hour, false},
		{"30m", 30 * time.Minute, false},
		{"300s", 300 * time.Second, false},
		{"1h30m", 1*time.Hour + 30*time.Minute, false},

		// sshca extensions over time.ParseDuration
		{"1d", 24 * time.Hour, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"1w", 7 * 24 * time.Hour, false},
		{"52w", 52 * 7 * 24 * time.Hour, false},

		// negative durations are accepted (mirrors time.ParseDuration);
		// callers (parseExpiry, cert list --expiring) check sign separately.
		{"-1d", -24 * time.Hour, false},
		{"-8h", -8 * time.Hour, false},

		// errors
		{"", 0, true},
		{"xyz", 0, true},
		{"8x", 0, true},
		{"d", 0, true}, // missing number prefix before unit
	}
	for _, c := range cases {
		got, err := parseSSHKeygenDuration(c.in)
		if c.err {
			if err == nil {
				t.Errorf("parseSSHKeygenDuration(%q) = %v, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseSSHKeygenDuration(%q) returned error %v, want duration %v", c.in, err, c.want)
			continue
		}
		if got != c.want {
			t.Errorf("parseSSHKeygenDuration(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// -----------------------------------------------------------------------------
// parseExpiry — combines ts + validity to compute expires_at
// -----------------------------------------------------------------------------

func TestParseExpiry(t *testing.T) {
	const ts = "2026-05-29T15:00:00Z"
	cases := []struct {
		validity string
		wantExp  string // RFC3339; "" when wantHas is false
		wantHas  bool
		err      bool
	}{
		// relative single-arg
		{"+8h", "2026-05-29T23:00:00Z", true, false},
		{"+52w", "2027-05-28T15:00:00Z", true, false},
		{"+30d", "2026-06-28T15:00:00Z", true, false},
		{"+90m", "2026-05-29T16:30:00Z", true, false},

		// always
		{"always", "", false, false},

		// from:to range
		{"always:always", "", false, false},
		{"always:+8h", "2026-05-29T23:00:00Z", true, false},
		{"20260601:20260701", "2026-07-01T00:00:00Z", true, false},

		// errors
		{"invalid", "", false, true},
		{"+invalid", "", false, true},
		{"+8x", "", false, true},
	}
	for _, c := range cases {
		got, has, err := parseExpiry(c.validity, ts)
		if c.err {
			if err == nil {
				t.Errorf("parseExpiry(%q, %q) = (%v, %v, nil), want error", c.validity, ts, got, has)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseExpiry(%q, %q) error: %v", c.validity, ts, err)
			continue
		}
		if has != c.wantHas {
			t.Errorf("parseExpiry(%q, %q) hasExpiry = %v, want %v", c.validity, ts, has, c.wantHas)
			continue
		}
		if c.wantExp != "" {
			want, _ := time.Parse(time.RFC3339, c.wantExp)
			if !got.Equal(want) {
				t.Errorf("parseExpiry(%q, %q) = %v, want %v", c.validity, ts, got, want)
			}
		}
	}
}

func TestParseExpiry_InvalidTimestamp(t *testing.T) {
	_, _, err := parseExpiry("+8h", "not-a-timestamp")
	if err == nil {
		t.Errorf("expected error for invalid timestamp")
	}
}

// -----------------------------------------------------------------------------
// formatTimeLeft — human-readable signed duration
// -----------------------------------------------------------------------------

func TestFormatTimeLeft(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{3*time.Hour + 53*time.Minute, "3h53m0s"},
		{8 * time.Hour, "8h0m0s"},
		{-14 * time.Hour, "-14h0m0s"},
		{0, "0s"},
		{1*time.Minute + 30*time.Second, "1m0s"}, // seconds truncated
		{59 * time.Second, "0s"},                 // sub-minute truncated to 0
		{-3*time.Hour - 30*time.Minute, "-3h30m0s"},
	}
	for _, c := range cases {
		got := formatTimeLeft(c.d)
		if got != c.want {
			t.Errorf("formatTimeLeft(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

// -----------------------------------------------------------------------------
// Integration tests — exercise signCert + inferPrincipalFromCert against a
// real CA generated in t.TempDir. Requires ssh-keygen on the host.
// -----------------------------------------------------------------------------

func skipIfNoSSHKeygen(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not in PATH")
	}
}

func TestSignCert_UserCA_Integration(t *testing.T) {
	skipIfNoSSHKeygen(t)
	dir := t.TempDir()

	// Generate user CA inside the temp dir (sshca convention: <dir>/user_ca)
	caPath := filepath.Join(dir, userCAPrivName)
	if out, err := exec.Command(
		"ssh-keygen", "-t", "ed25519", "-f", caPath, "-N", "", "-C", "test user CA", "-q",
	).CombinedOutput(); err != nil {
		t.Fatalf("ca keygen: %v\n%s", err, out)
	}

	// Generate a test user keypair to sign
	keyPath := filepath.Join(dir, "alice")
	if out, err := exec.Command(
		"ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "", "-C", "alice", "-q",
	).CombinedOutput(); err != nil {
		t.Fatalf("user keygen: %v\n%s", err, out)
	}
	pubPath := keyPath + ".pub"

	// Sign it via signCert
	certFile, err := signCert(dir, "user", "gw-tunnel,gw-user", "+8h", "alice-test-123", pubPath)
	if err != nil {
		t.Fatalf("signCert: %v", err)
	}

	// Verify cert file exists where we expect
	wantCertFile := strings.TrimSuffix(pubPath, ".pub") + "-cert.pub"
	if certFile != wantCertFile {
		t.Errorf("signCert returned %q, want %q", certFile, wantCertFile)
	}
	if _, err := os.Stat(certFile); err != nil {
		t.Errorf("cert file missing: %v", err)
	}

	// Verify audit log was appended with the expected fields
	logPath := filepath.Join(dir, issuanceLogName)
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read issuance log: %v", err)
	}
	log := string(data)
	for _, want := range []string{
		`"ca":"user"`,
		`"key_id":"alice-test-123"`,
		`"principals":"gw-tunnel,gw-user"`,
		`"valid":"+8h"`,
	} {
		if !strings.Contains(log, want) {
			t.Errorf("audit log missing %q\nlog:\n%s", want, log)
		}
	}

	// Verify inferPrincipalFromCert can read the cert back
	inferred := inferPrincipalFromCert(certFile)
	// inferPrincipalFromCert joins multi-principal lists with commas.
	if inferred != "gw-tunnel,gw-user" {
		t.Errorf("inferPrincipalFromCert = %q, want %q", inferred, "gw-tunnel,gw-user")
	}
}

func TestSignCert_HostCA_Integration(t *testing.T) {
	skipIfNoSSHKeygen(t)
	dir := t.TempDir()

	// Generate host CA
	hostCAPath := filepath.Join(dir, hostCAPrivName)
	if out, err := exec.Command(
		"ssh-keygen", "-t", "ed25519", "-f", hostCAPath, "-N", "", "-C", "test host CA", "-q",
	).CombinedOutput(); err != nil {
		t.Fatalf("host ca keygen: %v\n%s", err, out)
	}

	// Generate a fake host key to sign
	hostKeyPath := filepath.Join(dir, "ssh_host_ed25519_key")
	if out, err := exec.Command(
		"ssh-keygen", "-t", "ed25519", "-f", hostKeyPath, "-N", "", "-C", "test-host", "-q",
	).CombinedOutput(); err != nil {
		t.Fatalf("host keygen: %v\n%s", err, out)
	}

	certFile, err := signCert(dir, "host", "test-host,127.0.0.1", "+52w", "test-host-cert", hostKeyPath+".pub")
	if err != nil {
		t.Fatalf("signCert host: %v", err)
	}
	if _, err := os.Stat(certFile); err != nil {
		t.Errorf("cert file missing: %v", err)
	}

	// Confirm it's marked as a host cert (the -L output says "host certificate")
	out, _ := exec.Command("ssh-keygen", "-L", "-f", certFile).CombinedOutput()
	if !strings.Contains(string(out), "host certificate") {
		t.Errorf("cert not marked as host certificate:\n%s", out)
	}
}

func TestSignCert_InvalidCAArg(t *testing.T) {
	dir := t.TempDir()
	_, err := signCert(dir, "neither-user-nor-host", "p", "+8h", "k", "/nonexistent")
	if err == nil {
		t.Errorf("expected error for invalid --ca")
	}
}

func TestSignCert_MissingCA(t *testing.T) {
	dir := t.TempDir() // dir exists but no user_ca file inside
	_, err := signCert(dir, "user", "p", "+8h", "k", "/nonexistent")
	if err == nil {
		t.Errorf("expected error when CA private key missing")
	}
	if !strings.Contains(err.Error(), "CA key not found") {
		t.Errorf("error doesn't mention missing CA key: %v", err)
	}
}

// -----------------------------------------------------------------------------
// rotate — replace a CA and re-sign its certificates
// -----------------------------------------------------------------------------

func TestResignValidity(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, "2026-05-29T17:00:00Z")
	const ts = "2026-05-29T15:00:00Z"
	cases := []struct {
		valid, want string
		skip        bool
	}{
		{"+8h", "+21600s", false},
		{"always:+8h", "+21600s", false},
		{"20260601:20260701", "20260601:20260701", false},
		{"always", "always", false},
		{"+1h", "", true},               // expired at 16:00
		{"20260101:20260201", "", true}, // expired absolute
		{"+8x", "", true},               // not understood
	}
	for _, c := range cases {
		got, reason := resignValidity(logEntry{TS: ts, Valid: c.valid}, now)
		if (reason != "") != c.skip || got != c.want {
			t.Errorf("resignValidity(%q) = (%q, %q), want (%q, skip=%v)", c.valid, got, reason, c.want, c.skip)
		}
	}
}

// fingerprint returns the SHA256 fingerprint of a public key file, or of the
// signing CA of a certificate file.
func fingerprint(t *testing.T, file string) string {
	t.Helper()
	args, prefix := []string{"-lf", file}, ""
	if strings.HasSuffix(file, "-cert.pub") {
		args, prefix = []string{"-L", "-f", file}, "Signing CA:"
	}
	out, err := exec.Command("ssh-keygen", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen on %s: %v\n%s", file, err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), prefix) {
			continue
		}
		for _, f := range strings.Fields(line) {
			if strings.HasPrefix(f, "SHA256:") {
				return f
			}
		}
	}
	t.Fatalf("no fingerprint in ssh-keygen output for %s:\n%s", file, out)
	return ""
}

func TestRotateCA_Integration(t *testing.T) {
	skipIfNoSSHKeygen(t)
	dir := t.TempDir()
	for _, name := range []string{userCAPrivName, hostCAPrivName, "alice", "bob", "carol", "dave", "web"} {
		if out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-f", filepath.Join(dir, name), "-N", "", "-q").CombinedOutput(); err != nil {
			t.Fatalf("keygen %s: %v\n%s", name, err, out)
		}
	}
	pub := func(name string) string { return filepath.Join(dir, name+".pub") }
	sign := func(ca, name, valid string) string {
		cert, err := signCert(dir, ca, name, valid, name+"-id", pub(name))
		if err != nil {
			t.Fatalf("signCert %s: %v", name, err)
		}
		return cert
	}
	sign("user", "alice", "+1h")
	aliceCert := sign("user", "alice", "+8h") // latest entry for alice wins
	sign("user", "bob", "+8h")
	carolCert := sign("user", "carol", "+8h")
	sign("user", "dave", "20200101:20200102")
	webCert := sign("host", "web", "+52w")
	oldUserFP := fingerprint(t, filepath.Join(dir, userCAPubName))
	webBefore, _ := os.ReadFile(webCert)

	revoke := exec.Command("ssh-keygen", "-k", "-f", filepath.Join(dir, krlName), "-s", filepath.Join(dir, userCAPubName), "-")
	revoke.Stdin = strings.NewReader("id: bob-id\n")
	if out, err := revoke.CombinedOutput(); err != nil {
		t.Fatalf("krl: %v\n%s", err, out)
	}
	os.Remove(carolCert)

	if err := rotateCA(dir, "user"); err != nil {
		t.Fatalf("rotateCA: %v", err)
	}

	newUserFP := fingerprint(t, filepath.Join(dir, userCAPubName))
	if newUserFP == oldUserFP {
		t.Fatalf("user CA unchanged after rotation")
	}
	if fp := fingerprint(t, filepath.Join(dir, userCAPrivName+".prev.pub")); fp != oldUserFP {
		t.Errorf("user_ca.prev.pub fingerprint = %s, want the old CA %s", fp, oldUserFP)
	}
	if st, err := os.Stat(filepath.Join(dir, userCAPrivName)); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("new user_ca: stat %v, err %v; want mode 0600", st, err)
	}
	newPub, _ := os.ReadFile(filepath.Join(dir, userCAPubName))
	oldPub, _ := os.ReadFile(filepath.Join(dir, userCAPrivName+".prev.pub"))
	transition, _ := os.ReadFile(filepath.Join(dir, userCAPrivName+".transition.pub"))
	if string(transition) != string(newPub)+string(oldPub) {
		t.Errorf("transition file = %q, want new then old public key", transition)
	}

	if fp := fingerprint(t, aliceCert); fp != newUserFP {
		t.Errorf("alice cert signed by %s, want the new CA %s", fp, newUserFP)
	}
	if got := inferPrincipalFromCert(aliceCert); got != "alice" {
		t.Errorf("alice principals = %q, want alice", got)
	}
	if fp := fingerprint(t, filepath.Join(dir, "bob-cert.pub")); fp != oldUserFP {
		t.Errorf("revoked bob cert re-signed by %s", fp)
	}
	if fp := fingerprint(t, filepath.Join(dir, "dave-cert.pub")); fp != oldUserFP {
		t.Errorf("expired dave cert re-signed by %s", fp)
	}
	if _, err := os.Stat(carolCert); err == nil {
		t.Errorf("carol cert re-signed although its cert file was missing")
	}
	if webAfter, _ := os.ReadFile(webCert); string(webAfter) != string(webBefore) {
		t.Errorf("host cert changed by a user CA rotation")
	}

	data, _ := os.ReadFile(filepath.Join(dir, issuanceLogName))
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 7 {
		t.Fatalf("issuance log has %d lines, want 6 signatures + 1 re-signature:\n%s", len(lines), data)
	}
	var last logEntry
	if err := json.Unmarshal([]byte(lines[6]), &last); err != nil {
		t.Fatal(err)
	}
	secs, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(last.Valid, "+"), "s"))
	if last.KeyID != "alice-id" || err != nil || secs <= 8*3600-60 || secs > 8*3600 {
		t.Errorf("re-signature log entry = %+v, want key_id alice-id and about +28800s", last)
	}

	if err := rotateCA(dir, "user"); err == nil || !strings.Contains(err.Error(), "in progress") {
		t.Errorf("second rotation: err = %v, want refusal while user_ca.prev exists", err)
	}
}
