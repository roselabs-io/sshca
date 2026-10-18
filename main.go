// sshca — SSH-only certificate authority and management CLI.
//
// Single binary, two intended deps, JSONL audit by default.
// Bus-factor-zero design: operable without tribal knowledge.
// See docs/decisions/inherited.md for the upstream ADRs that motivated this tool.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/urfave/cli/v3"
)

// version is the sshca tool version. Defaults to "0.1.0-dev" during
// local development; release builds override via:
//
//	go build -ldflags "-X main.version=<tag>"
//
// See .github/workflows/release.yml.
var version = "0.1.0-dev"

// -----------------------------------------------------------------------------
// CA artifact paths
// -----------------------------------------------------------------------------

const (
	defaultCADir    = "ca"
	userCAPrivName  = "user_ca"
	userCAPubName   = "user_ca.pub"
	hostCAPrivName  = "host_ca"
	hostCAPubName   = "host_ca.pub"
	issuanceLogName = "issuance-log.jsonl"
	krlName         = "revoked_keys.krl"
)

func caDir() string {
	if d := os.Getenv("SSHCA_CA_DIR"); d != "" {
		return d
	}
	return defaultCADir
}

func caDirFromFlag(cmd *cli.Command) string {
	if d := cmd.String("dir"); d != "" {
		return d
	}
	return caDir()
}

// -----------------------------------------------------------------------------
// CA — init + show
// -----------------------------------------------------------------------------

func caInitCmd(_ context.Context, cmd *cli.Command) error {
	dir := caDirFromFlag(cmd)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return cli.Exit(err.Error(), 1)
	}
	for _, c := range []struct {
		name, priv, comment string
	}{
		{"user CA", filepath.Join(dir, userCAPrivName), "sshca user CA " + time.Now().Format("20060102")},
		{"host CA", filepath.Join(dir, hostCAPrivName), "sshca host CA " + time.Now().Format("20060102")},
	} {
		if _, err := os.Stat(c.priv); err == nil {
			return cli.Exit(fmt.Sprintf("%s already exists at %s — refusing to overwrite", c.name, c.priv), 1)
		}
		out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-f", c.priv, "-N", "", "-C", c.comment, "-q").CombinedOutput()
		if err != nil {
			return cli.Exit(fmt.Sprintf("ssh-keygen %s: %v\n%s", c.name, err, out), 1)
		}
		if err := os.Chmod(c.priv, 0o600); err != nil {
			return cli.Exit(err.Error(), 1)
		}
		fmt.Printf("Generated %s at %s\n", c.name, c.priv)
	}
	fmt.Println()
	return caShowCmd(context.Background(), cmd)
}

func caShowCmd(_ context.Context, cmd *cli.Command) error {
	dir := caDirFromFlag(cmd)
	for _, c := range []struct{ name, pub string }{
		{"user CA", filepath.Join(dir, userCAPubName)},
		{"host CA", filepath.Join(dir, hostCAPubName)},
	} {
		pubBytes, err := os.ReadFile(c.pub)
		if err != nil {
			fmt.Printf("%-8s  (missing at %s — run `sshca ca init`)\n", c.name, c.pub)
			continue
		}
		fpOut, _ := exec.Command("ssh-keygen", "-lf", c.pub).CombinedOutput()
		fmt.Printf("%-8s  %s", c.name, string(pubBytes))
		fmt.Printf("          %s", string(fpOut))
	}
	return nil
}

// -----------------------------------------------------------------------------
// Cert — shared signing helper + audit log
// -----------------------------------------------------------------------------

// signCert wraps `ssh-keygen -s` and appends a JSONL entry to the audit log.
// Returns the cert file path on success.
//
// The audit log schema (at <dir>/issuance-log.jsonl) is part of sshca's
// contract surface — downstream consumers depend on it. See
// docs/reference/contracts.md (TBD).
func signCert(dir, ca, principal, valid, keyID, pubkeyFile string) (certFile string, err error) {
	var caPriv string
	switch ca {
	case "user":
		caPriv = filepath.Join(dir, userCAPrivName)
	case "host":
		caPriv = filepath.Join(dir, hostCAPrivName)
	default:
		return "", fmt.Errorf("ca must be 'user' or 'host', got %q", ca)
	}
	if _, err := os.Stat(caPriv); err != nil {
		return "", fmt.Errorf("CA key not found at %s — run `sshca ca init` first", caPriv)
	}
	args := []string{"-s", caPriv, "-I", keyID, "-n", principal, "-V", valid}
	if ca == "host" {
		args = append(args, "-h")
	}
	args = append(args, pubkeyFile)
	if out, err := exec.Command("ssh-keygen", args...).CombinedOutput(); err != nil {
		return "", fmt.Errorf("ssh-keygen sign: %w\n%s", err, out)
	}
	certFile = strings.TrimSuffix(pubkeyFile, ".pub") + "-cert.pub"
	if _, err := os.Stat(certFile); err != nil {
		return certFile, fmt.Errorf("expected cert at %s but: %w", certFile, err)
	}
	logPath := filepath.Join(dir, issuanceLogName)
	entry := fmt.Sprintf(`{"ts":%q,"ca":%q,"key_id":%q,"principals":%q,"valid":%q,"pubkey":%q,"cert":%q}`+"\n",
		time.Now().UTC().Format(time.RFC3339),
		ca, keyID, principal, valid, pubkeyFile, certFile,
	)
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return certFile, fmt.Errorf("opening issuance log: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(entry); err != nil {
		return certFile, fmt.Errorf("writing issuance log: %w", err)
	}
	return certFile, nil
}

// inferPrincipalFromCert reads `ssh-keygen -L -f <cert>` output and extracts
// the principals list (comma-joined). Returns "" if the cert can't be read
// or has no principals.
//
// Boundary detection: principal entries are indented MORE than the
// "Principals:" header line. Next section header (Critical Options, Extensions)
// sits at the same indent as "Principals:" → ends the section.
func inferPrincipalFromCert(certFile string) string {
	out, err := exec.Command("ssh-keygen", "-L", "-f", certFile).CombinedOutput()
	if err != nil {
		return ""
	}
	indentOf := func(s string) int {
		return len(s) - len(strings.TrimLeft(s, "\t "))
	}
	var principals []string
	inSection := false
	sectionIndent := -1
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if !inSection {
			if strings.HasPrefix(trimmed, "Principals:") {
				inSection = true
				sectionIndent = indentOf(line)
			}
			continue
		}
		if line == "" || indentOf(line) <= sectionIndent {
			break
		}
		if trimmed != "" {
			principals = append(principals, trimmed)
		}
	}
	return strings.Join(principals, ",")
}

// -----------------------------------------------------------------------------
// Audit log + expiry parsing (used by cert list)
// -----------------------------------------------------------------------------

// logEntry mirrors the JSONL audit log schema at <ca-dir>/issuance-log.jsonl.
// This schema is part of sshca's contract surface — downstream consumers
// (the gateway product, future tools) depend on the field names + types.
type logEntry struct {
	TS         string `json:"ts"`
	CA         string `json:"ca"`
	KeyID      string `json:"key_id"`
	Principals string `json:"principals"`
	Valid      string `json:"valid"`
	Pubkey     string `json:"pubkey"`
	Cert       string `json:"cert"`
}

// parseSSHKeygenDuration parses ssh-keygen -V style durations: "8h", "52w",
// "30d", "60m", "300s". Go's time.ParseDuration handles s/m/h; we add d and w.
func parseSSHKeygenDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	last := s[len(s)-1:]
	if last == "w" || last == "d" {
		n, err := strconv.ParseInt(strings.TrimSuffix(s, last), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parsing %s: %w", s, err)
		}
		mul := 24 * time.Hour
		if last == "w" {
			mul = 7 * 24 * time.Hour
		}
		return time.Duration(n) * mul, nil
	}
	return time.ParseDuration(s)
}

// parseExpiry returns the cert's expires_at given its validity string (from
// the `valid` audit log field) and issuance timestamp (`ts`).
// Second return is true if the cert has a finite expiry; false for "always".
func parseExpiry(validStr, tsStr string) (time.Time, bool, error) {
	ts, err := time.Parse(time.RFC3339, tsStr)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("parsing ts: %w", err)
	}
	if validStr == "always" {
		return time.Time{}, false, nil
	}
	if strings.HasPrefix(validStr, "+") && !strings.Contains(validStr, ":") {
		d, err := parseSSHKeygenDuration(strings.TrimPrefix(validStr, "+"))
		if err != nil {
			return time.Time{}, false, err
		}
		return ts.Add(d), true, nil
	}
	if strings.Contains(validStr, ":") {
		parts := strings.SplitN(validStr, ":", 2)
		upper := parts[1]
		if upper == "always" {
			return time.Time{}, false, nil
		}
		if strings.HasPrefix(upper, "+") {
			d, err := parseSSHKeygenDuration(strings.TrimPrefix(upper, "+"))
			if err != nil {
				return time.Time{}, false, err
			}
			return ts.Add(d), true, nil
		}
		if len(upper) == 8 {
			t, err := time.Parse("20060102", upper)
			return t, err == nil, err
		}
		if len(upper) == 14 {
			t, err := time.Parse("20060102150405", upper)
			return t, err == nil, err
		}
		return time.Time{}, false, fmt.Errorf("unparseable upper bound %q", upper)
	}
	return time.Time{}, false, fmt.Errorf("unparseable validity %q", validStr)
}

// formatTimeLeft returns a human-readable signed duration: "3h53m" for future,
// "-14h0m" for past. Truncated to minute precision.
func formatTimeLeft(d time.Duration) string {
	sign := ""
	if d < 0 {
		sign = "-"
		d = -d
	}
	return sign + d.Truncate(time.Minute).String()
}

// -----------------------------------------------------------------------------
// Cert — sign, list, inspect, renew, revoke, krl
// -----------------------------------------------------------------------------

func certSignCmd(_ context.Context, cmd *cli.Command) error {
	pubkeyFile := cmd.Args().First()
	if pubkeyFile == "" {
		return cli.Exit("usage: sshca cert sign --ca user|host --principal X --valid +8h --key-id ID <pubkey-file>", 1)
	}
	if _, err := os.Stat(pubkeyFile); err != nil {
		return cli.Exit(fmt.Sprintf("pubkey file: %v", err), 1)
	}
	ca := cmd.String("ca")
	principal := cmd.String("principal")
	if principal == "" {
		return cli.Exit("--principal is required (comma-separated for multiple)", 1)
	}
	valid := cmd.String("valid")
	if valid == "" {
		valid = "+8h"
	}
	keyID := cmd.String("key-id")
	if keyID == "" {
		return cli.Exit("--key-id is required (this is your audit trail)", 1)
	}
	certFile, err := signCert(caDirFromFlag(cmd), ca, principal, valid, keyID, pubkeyFile)
	if err != nil {
		return cli.Exit(err.Error(), 1)
	}
	fmt.Printf("✓ cert signed: %s\n\n", certFile)
	inspectOut, _ := exec.Command("ssh-keygen", "-L", "-f", certFile).CombinedOutput()
	fmt.Print(string(inspectOut))
	return nil
}

// certListCmd: tails the JSONL audit log.
//   - No filters: raw JSONL dump (backwards-compatible).
//   - --principal X: tabular filter to that principal.
//   - --expiring DUR / --expired: tabular filter by expiry; can compose with --principal.
func certListCmd(_ context.Context, cmd *cli.Command) error {
	dir := caDirFromFlag(cmd)
	logPath := filepath.Join(dir, issuanceLogName)
	data, err := os.ReadFile(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("(no certs issued yet — log not at %s)\n", logPath)
			return nil
		}
		return cli.Exit(err.Error(), 1)
	}

	principalFilter := cmd.String("principal")
	expiringWithin := cmd.String("expiring")
	showExpired := cmd.Bool("expired")

	// No filters → raw JSONL (backwards-compatible).
	if principalFilter == "" && expiringWithin == "" && !showExpired {
		fmt.Print(string(data))
		return nil
	}

	// Parse all entries.
	var entries []logEntry
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var entry logEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}

	// Apply principal filter if requested.
	if principalFilter != "" {
		var filtered []logEntry
		for _, e := range entries {
			for _, p := range strings.Split(e.Principals, ",") {
				if strings.TrimSpace(p) == principalFilter {
					filtered = append(filtered, e)
					break
				}
			}
		}
		entries = filtered
	}

	// Expiry-based view (either --expiring or --expired set).
	if expiringWithin != "" || showExpired {
		var window time.Duration
		if expiringWithin != "" {
			window, err = parseSSHKeygenDuration(expiringWithin)
			if err != nil {
				return cli.Exit(fmt.Sprintf("invalid --expiring value %q: %v", expiringWithin, err), 1)
			}
		}
		now := time.Now().UTC()
		type entryWithExpiry struct {
			logEntry
			expiresAt time.Time
		}
		var matches []entryWithExpiry
		for _, e := range entries {
			exp, has, parseErr := parseExpiry(e.Valid, e.TS)
			if parseErr != nil || !has {
				continue
			}
			isExpired := !exp.After(now)
			isExpiring := exp.After(now) && exp.Before(now.Add(window))
			include := (showExpired && isExpired) || (expiringWithin != "" && isExpiring)
			if include {
				matches = append(matches, entryWithExpiry{logEntry: e, expiresAt: exp})
			}
		}
		sort.Slice(matches, func(i, j int) bool {
			return matches[i].expiresAt.Before(matches[j].expiresAt)
		})

		var header string
		switch {
		case expiringWithin != "" && showExpired:
			header = fmt.Sprintf("Certs expiring within %s or already expired (relative to %s):", expiringWithin, now.Format(time.RFC3339))
		case expiringWithin != "":
			header = fmt.Sprintf("Certs expiring within %s (relative to %s):", expiringWithin, now.Format(time.RFC3339))
		case showExpired:
			header = fmt.Sprintf("Expired certs (relative to %s):", now.Format(time.RFC3339))
		}
		if principalFilter != "" {
			header += fmt.Sprintf(" — filtered to principal=%q", principalFilter)
		}
		fmt.Println(header)
		if len(matches) == 0 {
			fmt.Println()
			fmt.Println("(no matching certs)")
			return nil
		}
		fmt.Println()
		fmt.Printf("%-55s %-15s %-21s %-12s %s\n", "KEY_ID", "PRINCIPALS", "EXPIRES_AT", "TIME_LEFT", "STATUS")
		for _, m := range matches {
			kid := m.KeyID
			if len(kid) > 55 {
				kid = kid[:54] + "…"
			}
			principals := m.Principals
			if len(principals) > 15 {
				principals = principals[:14] + "…"
			}
			status := "EXPIRING"
			if !m.expiresAt.After(now) {
				status = "EXPIRED"
			}
			fmt.Printf("%-55s %-15s %-21s %-12s %s\n",
				kid, principals,
				m.expiresAt.Format(time.RFC3339),
				formatTimeLeft(m.expiresAt.Sub(now)),
				status,
			)
		}
		fmt.Println()
		fmt.Println("Use `sshca cert renew --pubkey-file <pubkey>` to re-sign with the existing cert's principal.")
		return nil
	}

	// Principal-only filter (tabular).
	if len(entries) == 0 {
		fmt.Printf("(no certs with principal=%q in issuance log)\n", principalFilter)
		return nil
	}
	fmt.Printf("Certs with principal=%q — chronological, most recent last:\n\n", principalFilter)
	fmt.Printf("%-55s %-10s %-22s\n", "KEY_ID", "VALIDITY", "ISSUED (UTC)")
	for _, e := range entries {
		kid := e.KeyID
		if len(kid) > 55 {
			kid = kid[:54] + "…"
		}
		fmt.Printf("%-55s %-10s %-22s\n", kid, e.Valid, e.TS)
	}
	fmt.Println()
	fmt.Println("Use `sshca cert inspect <cert-file>` for full cert details (validity window etc.).")
	return nil
}

func certInspectCmd(_ context.Context, cmd *cli.Command) error {
	f := cmd.Args().First()
	if f == "" {
		return cli.Exit("usage: sshca cert inspect <cert-file>", 1)
	}
	out, err := exec.Command("ssh-keygen", "-L", "-f", f).CombinedOutput()
	if err != nil {
		return cli.Exit(fmt.Sprintf("%v\n%s", err, out), 1)
	}
	fmt.Print(string(out))
	return nil
}

// certRenewCmd: re-sign with principal inferred from existing <pubkey>-cert.pub.
// --ship DEST takes an explicit scp target (e.g. user@host:/path/to/cert).
func certRenewCmd(_ context.Context, cmd *cli.Command) error {
	pubkeyFile := cmd.String("pubkey-file")
	if pubkeyFile == "" {
		return cli.Exit("--pubkey-file is required (the pubkey to re-sign)", 1)
	}
	if _, err := os.Stat(pubkeyFile); err != nil {
		return cli.Exit(fmt.Sprintf("pubkey file: %v", err), 1)
	}
	principal := cmd.String("principal")
	if principal == "" {
		existingCert := strings.TrimSuffix(pubkeyFile, ".pub") + "-cert.pub"
		if _, err := os.Stat(existingCert); err == nil {
			principal = inferPrincipalFromCert(existingCert)
		}
	}
	if principal == "" {
		return cli.Exit("--principal is required (could not infer from existing cert)", 1)
	}
	ca := cmd.String("ca")
	if ca == "" {
		ca = "user"
	}
	valid := cmd.String("valid")
	if valid == "" {
		valid = "+8h"
	}
	namePart := cmd.String("name")
	if namePart == "" {
		namePart = strings.TrimSuffix(filepath.Base(pubkeyFile), ".pub")
	}
	keyID := fmt.Sprintf("%s-%s", namePart, time.Now().UTC().Format("20060102T1504Z"))

	certFile, err := signCert(caDirFromFlag(cmd), ca, principal, valid, keyID, pubkeyFile)
	if err != nil {
		return cli.Exit(err.Error(), 1)
	}
	fmt.Printf("✓ cert renewed: %s\n", certFile)
	fmt.Printf("  principal: %s\n", principal)
	fmt.Printf("  valid:     %s\n", valid)
	fmt.Printf("  key-id:    %s\n", keyID)

	if dest := cmd.String("ship"); dest != "" {
		fmt.Println()
		if out, err := exec.Command("scp", "-o", "BatchMode=yes", certFile, dest).CombinedOutput(); err != nil {
			return cli.Exit(fmt.Sprintf("scp to %s: %v\n%s", dest, err, out), 1)
		}
		fmt.Printf("✓ shipped to %s\n", dest)
	}
	return nil
}

// certRevokeCmd: add a revocation to the local KRL. --ship DEST takes an
// explicit scp target (e.g. user@host:/etc/ssh/revoked_keys.krl).
// sshd re-reads the KRL on every connection, so no reload is needed once shipped.
func certRevokeCmd(_ context.Context, cmd *cli.Command) error {
	keyID := cmd.String("key-id")
	serial := int64(cmd.Int("serial"))
	pubkey := cmd.String("pubkey-file")
	if keyID == "" && serial == 0 && pubkey == "" {
		return cli.Exit("one of --key-id, --serial, or --pubkey-file is required", 1)
	}
	ca := cmd.String("ca")
	if ca != "user" && ca != "host" {
		return cli.Exit("--ca must be 'user' or 'host'", 1)
	}
	dir := caDirFromFlag(cmd)
	var caPub string
	if ca == "user" {
		caPub = filepath.Join(dir, userCAPubName)
	} else {
		caPub = filepath.Join(dir, hostCAPubName)
	}
	if _, err := os.Stat(caPub); err != nil {
		return cli.Exit(fmt.Sprintf("CA pubkey not found at %s", caPub), 1)
	}
	krlPath := filepath.Join(dir, krlName)

	var specLines []string
	if keyID != "" {
		specLines = append(specLines, "id: "+keyID)
	}
	if serial != 0 {
		specLines = append(specLines, fmt.Sprintf("serial: %d", serial))
	}
	spec := strings.Join(specLines, "\n") + "\n"

	args := []string{"-k"}
	if _, err := os.Stat(krlPath); err == nil {
		args = append(args, "-u")
	}
	args = append(args, "-f", krlPath, "-s", caPub)
	if pubkey != "" {
		args = append(args, pubkey)
	} else {
		args = append(args, "-") // stdin
	}

	c := exec.Command("ssh-keygen", args...)
	if pubkey == "" {
		c.Stdin = strings.NewReader(spec)
	}
	out, err := c.CombinedOutput()
	if err != nil {
		return cli.Exit(fmt.Sprintf("ssh-keygen krl: %v\n%s", err, out), 1)
	}

	fmt.Printf("✓ revocation added to %s\n", krlPath)

	if dest := cmd.String("ship"); dest != "" {
		fmt.Println()
		if out, err := exec.Command("scp", "-o", "BatchMode=yes", krlPath, dest).CombinedOutput(); err != nil {
			return cli.Exit(fmt.Sprintf("scp to %s: %v\n%s", dest, err, out), 1)
		}
		fmt.Printf("✓ shipped to %s — sshd re-reads KRL on every connection, no reload needed\n", dest)
	} else {
		fmt.Println()
		fmt.Println("Next: ship the KRL to wherever sshd reads it (e.g. /etc/ssh/revoked_keys.krl):")
		if keyID != "" {
			fmt.Printf("  sshca cert revoke --key-id %q --ca %s --ship user@host:/etc/ssh/revoked_keys.krl\n", keyID, ca)
		}
		fmt.Println("  OR")
		fmt.Printf("  scp %s user@host:/etc/ssh/revoked_keys.krl\n", krlPath)
	}
	return nil
}

func certKrlCmd(_ context.Context, cmd *cli.Command) error {
	dir := caDirFromFlag(cmd)
	krlPath := filepath.Join(dir, krlName)
	if _, err := os.Stat(krlPath); err != nil {
		fmt.Printf("(no local KRL at %s — no revocations yet)\n", krlPath)
		return nil
	}
	fmt.Printf("Local KRL: %s\n", krlPath)
	st, _ := os.Stat(krlPath)
	fmt.Printf("  size: %d bytes\n", st.Size())
	fmt.Printf("  use `ssh-keygen -Q -f %s -s %s/user_ca.pub <cert-or-pubkey>` to test specific revocations\n", krlPath, dir)
	return nil
}

// -----------------------------------------------------------------------------
// Rotate — replace a CA and re-sign its certificates
// -----------------------------------------------------------------------------

// rotateCA keeps the current <ca>_ca keypair as <ca>_ca.prev, generates a new
// one, writes <ca>_ca.transition.pub (new key, then old) and re-signs with the
// new CA the latest certificate of each public key in the issuance log.
// It returns an error when the CA cannot be replaced or a re-signature fails.
func rotateCA(dir, ca string) error {
	var priv string
	switch ca {
	case "user":
		priv = filepath.Join(dir, userCAPrivName)
	case "host":
		priv = filepath.Join(dir, hostCAPrivName)
	default:
		return fmt.Errorf("ca must be 'user' or 'host', got %q", ca)
	}
	prev := priv + ".prev"
	if _, err := os.Stat(priv); err != nil {
		return fmt.Errorf("CA key not found at %s — run `sshca ca init` first", priv)
	}
	// os.Link fails when the target exists, so of two concurrent rotations
	// only one can save the current keypair, and a saved one is never replaced.
	if err := os.Link(priv, prev); err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s exists: a rotation of the %s CA is in progress (see README, CA rotation)", prev, ca)
		}
		return err
	}
	if err := os.Link(priv+".pub", prev+".pub"); err != nil {
		os.Remove(prev)
		return err
	}
	os.Remove(priv)
	os.Remove(priv + ".pub")
	comment := fmt.Sprintf("sshca %s CA %s", ca, time.Now().UTC().Format("20060102"))
	if out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-f", priv, "-N", "", "-C", comment, "-q").CombinedOutput(); err != nil {
		os.Remove(priv)
		os.Remove(priv + ".pub")
		os.Rename(prev, priv)
		os.Rename(prev+".pub", priv+".pub")
		return fmt.Errorf("ssh-keygen %s CA: %v\n%s", ca, err, out)
	}
	if err := os.Chmod(priv, 0o600); err != nil {
		return err
	}
	newPub, err := os.ReadFile(priv + ".pub")
	if err != nil {
		return err
	}
	oldPub, err := os.ReadFile(prev + ".pub")
	if err != nil {
		return err
	}
	transition := priv + ".transition.pub"
	if err := os.WriteFile(transition, append(newPub, oldPub...), 0o644); err != nil {
		return err
	}
	fmt.Printf("✓ %s CA rotated\n", ca)
	fmt.Printf("  new CA:     %s\n", priv)
	fmt.Printf("  old CA:     %s\n", prev)
	fmt.Printf("  transition: %s (trust this file on every machine until all certs are re-issued)\n\n", transition)

	data, err := os.ReadFile(filepath.Join(dir, issuanceLogName))
	if os.IsNotExist(err) {
		fmt.Println("(no issuance log — no certs to re-sign)")
		return nil
	}
	if err != nil {
		return err
	}
	latest := map[string]logEntry{}
	var pubkeys []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var e logEntry
		if json.Unmarshal([]byte(line), &e) != nil || e.CA != ca {
			continue
		}
		if _, seen := latest[e.Pubkey]; !seen {
			pubkeys = append(pubkeys, e.Pubkey)
		}
		latest[e.Pubkey] = e
	}

	krl := filepath.Join(dir, krlName)
	failed := 0
	for _, pub := range pubkeys {
		e := latest[pub]
		var valid, reason string
		if _, err := os.Stat(e.Pubkey); err != nil {
			reason = "public key file missing"
		} else if revoked, err := entryRevoked(krl, prev, e); err != nil {
			fmt.Printf("failed     %s: %v\n", e.Pubkey, err)
			failed++
			continue
		} else if revoked {
			reason = "revoked by " + krl
		} else {
			// Relative bounds are counted from here, so this runs just before signing.
			valid, reason = resignValidity(e, time.Now().UTC())
		}
		if reason != "" {
			fmt.Printf("skipped    %s: %s\n", e.Pubkey, reason)
			continue
		}
		certFile, err := signCert(dir, ca, e.Principals, valid, e.KeyID, e.Pubkey)
		if err != nil {
			fmt.Printf("failed     %s: %v\n", e.Pubkey, err)
			failed++
			continue
		}
		fmt.Printf("re-signed  %s (key-id %s, valid %s)\n", certFile, e.KeyID, valid)
	}
	if failed > 0 {
		return fmt.Errorf("%d re-signature(s) failed; the new CA and %s are in place", failed, transition)
	}
	return nil
}

// resignValidity returns the ssh-keygen -V value that gives a re-signed cert
// the start and expiry of the cert logged in e, or a reason not to re-sign it.
// ssh-keygen counts a relative bound from the time of signing, so a relative
// bound logged at the original issuance becomes signed seconds from now; an
// absolute or unbounded bound is reused as logged.
func resignValidity(e logEntry, now time.Time) (valid, skipReason string) {
	exp, has, err := parseExpiry(e.Valid, e.TS)
	if err != nil {
		return "", fmt.Sprintf("validity %q not understood: %v", e.Valid, err)
	}
	if has && exp.Sub(now) < time.Second {
		return "", "expired"
	}
	lower, upper, isRange := strings.Cut(e.Valid, ":")
	if !isRange {
		lower, upper = "", e.Valid
	}
	if has && strings.HasPrefix(upper, "+") {
		upper = fmt.Sprintf("+%ds", int64(exp.Sub(now)/time.Second))
	}
	if !isRange {
		return upper, ""
	}
	if strings.HasPrefix(lower, "+") || strings.HasPrefix(lower, "-") {
		d, err := parseSSHKeygenDuration(lower[1:])
		if err != nil {
			return "", fmt.Sprintf("validity %q not understood: %v", e.Valid, err)
		}
		ts, _ := time.Parse(time.RFC3339, e.TS)
		if lower[0] == '-' {
			d = -d
		}
		lower = fmt.Sprintf("%+ds", int64(ts.Add(d).Sub(now)/time.Second))
	}
	return lower + ":" + upper, ""
}

// entryRevoked reports whether the KRL at krl revokes the certificate logged
// in e. When that certificate file is missing, it checks a certificate of the
// same public key, key ID and principals signed by the old CA at prevPriv.
func entryRevoked(krl, prevPriv string, e logEntry) (bool, error) {
	if _, err := os.Stat(krl); err != nil {
		return false, nil
	}
	if _, err := os.Stat(e.Cert); err == nil {
		return certRevoked(krl, e.Cert)
	}
	tmp, err := os.MkdirTemp("", "sshca-rotate-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(tmp)
	pubBytes, err := os.ReadFile(e.Pubkey)
	if err != nil {
		return false, err
	}
	probe := filepath.Join(tmp, "probe.pub")
	if err := os.WriteFile(probe, pubBytes, 0o600); err != nil {
		return false, err
	}
	args := []string{"-s", prevPriv, "-I", e.KeyID, "-n", e.Principals, "-V", "+1m"}
	if e.CA == "host" {
		args = append(args, "-h")
	}
	if out, err := exec.Command("ssh-keygen", append(args, probe)...).CombinedOutput(); err != nil {
		return false, fmt.Errorf("ssh-keygen probe cert: %v\n%s", err, out)
	}
	return certRevoked(krl, filepath.Join(tmp, "probe-cert.pub"))
}

// certRevoked reports whether the KRL at krl revokes certFile. A missing KRL
// revokes nothing.
func certRevoked(krl, certFile string) (bool, error) {
	if _, err := os.Stat(krl); err != nil {
		return false, nil
	}
	out, err := exec.Command("ssh-keygen", "-Q", "-f", krl, certFile).CombinedOutput()
	if err == nil {
		return false, nil
	}
	// ssh-keygen -Q exits 1 when a key is revoked and 255 on other errors.
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
		return true, nil
	}
	return false, fmt.Errorf("ssh-keygen -Q: %v\n%s", err, out)
}

func rotateCmd(_ context.Context, cmd *cli.Command) error {
	if err := rotateCA(caDirFromFlag(cmd), cmd.String("ca")); err != nil {
		return cli.Exit(err.Error(), 1)
	}
	fmt.Println()
	fmt.Println("Next: deliver the re-signed certs and follow the runbook in README.md, CA rotation.")
	return nil
}

// -----------------------------------------------------------------------------
// main — wire up commands
// -----------------------------------------------------------------------------

func main() {
	dirFlag := &cli.StringFlag{Name: "dir", Usage: "use a CA directory other than ./ca; takes precedence over $SSHCA_CA_DIR"}

	app := &cli.Command{
		Name:    "sshca",
		Usage:   "SSH-only certificate authority and management CLI — bus-factor-zero by design",
		Version: version,
		Commands: []*cli.Command{
			{
				Name:  "ca",
				Usage: "manage the local CA (thin wrapper around ssh-keygen -s)",
				Commands: []*cli.Command{
					{
						Name:   "init",
						Usage:  "generate user_ca + host_ca keypairs (refuses to overwrite existing)",
						Flags:  []cli.Flag{dirFlag},
						Action: caInitCmd,
					},
					{
						Name:   "show",
						Usage:  "print CA pubkeys + fingerprints",
						Flags:  []cli.Flag{dirFlag},
						Action: caShowCmd,
					},
				},
			},
			{
				Name:  "cert",
				Usage: "sign, list, inspect, renew, revoke certificates",
				Commands: []*cli.Command{
					{
						Name:      "sign",
						Usage:     "sign a pubkey into a cert using the local CA",
						ArgsUsage: "<pubkey-file>",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "ca", Usage: "user|host: user signs a client key for login, host signs a server host key", Required: true},
							&cli.StringFlag{Name: "principal", Usage: "usernames (user CA) or hostnames (host CA) the cert is valid for, comma-separated", Required: true},
							&cli.StringFlag{Name: "valid", Usage: "set a validity other than '+8h', as ssh-keygen -V accepts it (e.g. '+52w', '20260601:20260701')"},
							&cli.StringFlag{Name: "key-id", Usage: "identifier written into the cert, the issuance log and sshd's auth log; used later to find or revoke the cert", Required: true},
							dirFlag,
						},
						Action: certSignCmd,
					},
					{
						Name:  "list",
						Usage: "tail the issuance log (raw JSONL by default; --principal / --expiring / --expired switch to a table)",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "principal", Usage: "show only certs issued to this principal, as a table"},
							&cli.StringFlag{Name: "expiring", Usage: "show certs that expire within DURATION (e.g. 24h, 7d, 4w), to find certs due for renewal"},
							&cli.BoolFlag{Name: "expired", Usage: "show certs that have already expired; combines with --expiring"},
							dirFlag,
						},
						Action: certListCmd,
					},
					{
						Name:      "inspect",
						Usage:     "show the contents of a cert file (wraps `ssh-keygen -L`)",
						ArgsUsage: "<cert-file>",
						Action:    certInspectCmd,
					},
					{
						Name:  "renew",
						Usage: "re-sign a pubkey with a fresh cert (principal inferred from existing cert)",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "pubkey-file", Usage: "public key to re-sign; its existing <name>-cert.pub is overwritten", Required: true},
							&cli.StringFlag{Name: "ca", Usage: "set to host when renewing a host cert; default user"},
							&cli.StringFlag{Name: "principal", Usage: "set principals when changing them or when no <name>-cert.pub exists to read them from, comma-separated"},
							&cli.StringFlag{Name: "valid", Usage: "set a validity other than '+8h', as ssh-keygen -V accepts it (e.g. '+52w')"},
							&cli.StringFlag{Name: "name", Usage: "key-id prefix, followed by a UTC timestamp; default the pubkey file name without .pub"},
							&cli.StringFlag{Name: "ship", Usage: "copy the new cert with scp to this destination (e.g. 'user@host:/path'); omit to leave it local"},
							dirFlag,
						},
						Action: certRenewCmd,
					},
					{
						Name:  "revoke",
						Usage: "add a revocation entry to the KRL (by --key-id, --serial, or --pubkey-file)",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "ca", Usage: "the CA that signed the cert being revoked: user|host", Required: true},
							&cli.StringFlag{Name: "key-id", Usage: "revoke every cert carrying this key-id, as recorded in the issuance log"},
							&cli.IntFlag{Name: "serial", Usage: "revoke by serial number, shown by cert inspect; certs from cert sign have serial 0, which this flag cannot revoke"},
							&cli.StringFlag{Name: "pubkey-file", Usage: "revoke a plain public key by file path; when set, --key-id and --serial are ignored"},
							&cli.StringFlag{Name: "ship", Usage: "copy the updated KRL with scp to this destination (e.g. 'user@host:/etc/ssh/revoked_keys.krl'); omit to leave it local"},
							dirFlag,
						},
						Action: certRevokeCmd,
					},
					{
						Name:   "krl",
						Usage:  "show local KRL metadata",
						Flags:  []cli.Flag{dirFlag},
						Action: certKrlCmd,
					},
				},
			},
			{
				Name:  "rotate",
				Usage: "replace the user or host CA, keep the old one as <ca>_ca.prev, write <ca>_ca.transition.pub and re-sign the CA's certs from the issuance log",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "ca", Usage: "the CA to replace: user|host", Required: true},
					dirFlag,
				},
				Action: rotateCmd,
			},
		},
	}
	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
