package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

// SecretStore keeps one secret (the serialized credential) for this installation.
type SecretStore interface {
	Get() ([]byte, error) // nil, nil when there is none
	Set([]byte) error
	Delete() error
	Name() string
}

const (
	keychainService = "ai.sigill.claude-code"
)

// DefaultStore returns the installation's credential store. Every mode — OS keychain, Secret Service,
// private file only (SIGILL_CREDENTIAL_STORE=file, or no keychain usable in this invocation) — goes through
// one authority protocol (see authority), so switching between them can never read a stale copy.
//
// Which OS store this installation could have used depends only on the OS, never on whether its helper is
// on PATH now: a helper that disappeared makes that store unreadable (uncertain), not absent.
func DefaultStore(dir string) SecretStore {
	a := &authority{file: &FileStore{Path: filepath.Join(dir, "credential.json")}, marker: filepath.Join(dir, "credential.store")}
	switch runtime.GOOS {
	case "darwin":
		a.osPrimary, a.primary = "keychain", &macKeychain{account: "default:" + dir} // one credential per data directory
		_, err := exec.LookPath("security")
		a.readOnlyPrimary = err != nil
	case "linux":
		a.osPrimary, a.primary = "secret-service", &secretService{account: "default:" + dir}
		_, err := exec.LookPath("secret-tool")
		a.readOnlyPrimary = err != nil || os.Getenv("DBUS_SESSION_BUS_ADDRESS") == ""
	}
	if os.Getenv("SIGILL_CREDENTIAL_STORE") == "file" {
		a.readOnlyPrimary = true // never written; still read where the marker names it, or to rule out a newer legacy copy
	}
	return a
}

// ErrCredentialAmbiguous: a credential stored by an earlier version exists in more than one place, or may
// exist in a store this invocation cannot read; which one is current cannot be known, so none is used.
var ErrCredentialAmbiguous = errors.New("the stored Sigill connection cannot be established unambiguously")

// authority keeps exactly one backend authoritative, named by a durable private marker (credential.store):
// "keychain", "secret-service", "file" or "none" (after a disconnect). Get reads only the named backend —
// if that backend is not usable in this invocation, it reports so instead of reading another one — so a
// superseded secret left anywhere else (a spent refresh token in a keychain that was briefly unavailable, a
// file left from a headless run) is never read. Set writes the new secret, then flips the marker; a crash in
// between leaves the previous consistent state (and the refresh protocol's in-flight marker makes it
// uncertain, never replayed). Delete writes the tombstone first.
//
// Stores written before markers existed are used only when every possible backend was read successfully
// and the result is unambiguous; a backend that could not be read (locked, helper missing) makes a legacy
// copy elsewhere uncertain, and the user reconnects. Get never writes: adopting legacy state (writing the
// marker) is Migrate, which runs only under the credential lock, where every marker writer is serialized.
type authority struct {
	primary         SecretStore // the OS store this installation could have used; nil when the OS has none
	osPrimary       string      // "keychain" | "secret-service" | "" — its marker name
	readOnlyPrimary bool        // never written in this invocation (helper missing, no session bus, or file-only)
	file            *FileStore
	marker          string
}

type storeMarker struct {
	Backend    string `json:"backend"` // keychain | secret-service | file | none ("primary" in 0.2.1–0.2.2)
	Generation int    `json:"generation"`
}

func (a *authority) Name() string {
	if a.writable() {
		return a.primary.Name() + " (file fallback)"
	}
	return "private file"
}

func (a *authority) writable() bool { return a.primary != nil && !a.readOnlyPrimary }

func (a *authority) readMarker() (*storeMarker, error) {
	raw, err := (&FileStore{Path: a.marker}).Get()
	if err != nil || len(raw) == 0 {
		return nil, err
	}
	var m storeMarker
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, errors.New("the credential store marker is unreadable")
	}
	if m.Backend == "primary" { // written by 0.2.1–0.2.2: this OS's store
		m.Backend = a.osPrimary
	}
	switch m.Backend {
	case "keychain", "secret-service", "file", "none":
		return &m, nil
	}
	return nil, errors.New("the credential store marker is unreadable")
}

func (a *authority) writeMarker(backend string, generation int) error {
	raw, _ := json.Marshal(storeMarker{Backend: backend, Generation: generation})
	return (&FileStore{Path: a.marker}).Set(raw) // durable: file and directory entry synced
}

func (a *authority) primaryID() string {
	if a.primary == nil {
		return ""
	}
	return a.osPrimary
}

// Get reads the credential. It never writes (see Migrate).
func (a *authority) Get() ([]byte, error) {
	m, err := a.readMarker()
	if err != nil {
		return nil, err
	}
	if m != nil {
		switch {
		case m.Backend == "none":
			return nil, nil // disconnected
		case m.Backend == "file":
			return a.file.Get()
		case m.Backend == a.primaryID():
			b, err := a.primary.Get()
			if err != nil {
				return nil, fmt.Errorf("the Sigill connection is stored in the %s, which cannot be read now: %w", m.Backend, err)
			}
			return b, nil
		default:
			return nil, fmt.Errorf("the Sigill connection is stored in the %s, which is not available now", m.Backend)
		}
	}
	b, _, err := a.legacy()
	return b, err
}

// legacy resolves a store written before markers existed: the secret and the backend holding it, or nil
// when nothing is stored. Any backend that could hold a newer copy but cannot be read makes a found copy
// uncertain; two different copies are ambiguous. Read-only.
func (a *authority) legacy() ([]byte, string, error) {
	fb, err := a.file.Get()
	if err != nil {
		return nil, "", fmt.Errorf("%w: the credential file cannot be read (%v)", ErrCredentialAmbiguous, err)
	}
	var pb []byte
	var perr error
	switch {
	case a.primary != nil:
		pb, perr = a.primary.Get()
	case a.osPrimary != "":
		perr = errors.New("not available in this invocation")
	}
	if perr != nil {
		if len(fb) == 0 {
			return nil, "", nil // nothing usable is stored: not connected (connecting writes a fresh marker)
		}
		return nil, "", fmt.Errorf("%w: the %s, which may hold a newer copy, cannot be read (%v)", ErrCredentialAmbiguous, a.osPrimary, perr)
	}
	switch {
	case len(pb) > 0 && len(fb) > 0:
		if !bytes.Equal(pb, fb) {
			return nil, "", ErrCredentialAmbiguous // two different secrets: never guess which is current
		}
		return pb, a.osPrimary, nil
	case len(pb) > 0:
		return pb, a.osPrimary, nil
	case len(fb) > 0:
		return fb, "file", nil
	}
	return nil, "", nil
}

// Migrate makes an unambiguous legacy store authoritative by writing its marker. It must run under the
// credential lock: there every marker writer (Set, Delete, Migrate) is serialized, so a migration decided
// on a stale read can never overwrite a marker written meanwhile. With a marker present it does nothing.
func (a *authority) Migrate() error {
	m, err := a.readMarker()
	if err != nil || m != nil {
		return err
	}
	b, backend, err := a.legacy()
	if err != nil || b == nil {
		return err
	}
	if err := a.writeMarker(backend, 1); err != nil {
		return err
	}
	if backend != "file" {
		_ = a.file.Delete() // unreadable under the marker anyway; removing it is housekeeping
	}
	return nil
}

func (a *authority) Set(b []byte) error {
	gen := 0
	if m, err := a.readMarker(); err == nil && m != nil {
		gen = m.Generation
	}
	backend := "file"
	if a.writable() && a.primary.Set(b) == nil {
		backend = a.primaryID()
	} else if err := a.file.Set(b); err != nil {
		return err
	}
	if err := a.writeMarker(backend, gen+1); err != nil {
		return err // not authoritative yet: the caller keeps treating the refresh as uncertain
	}
	// The other copy is unreadable under the marker anyway; removing it is housekeeping.
	if backend == "file" {
		if a.writable() {
			_ = a.primary.Delete()
		}
	} else {
		_ = a.file.Delete()
	}
	return nil
}

func (a *authority) Delete() error {
	gen := 0
	if m, err := a.readMarker(); err == nil && m != nil {
		gen = m.Generation
	}
	if err := a.writeMarker("none", gen+1); err != nil { // the tombstone first: nothing can be resurrected
		return err
	}
	if a.writable() {
		_ = a.primary.Delete()
	}
	return a.file.Delete()
}

// macKeychain uses `security`. The secret is written through `security -i` on STDIN, so it
// never appears in a process argument list; base64 keeps the interactive parser simple.
type macKeychain struct{ account string }

func (k *macKeychain) Name() string { return "macOS Keychain" }

func (k *macKeychain) Get() ([]byte, error) {
	out, err := exec.Command("security", "find-generic-password", "-s", keychainService, "-a", k.account, "-w").Output()
	return keychainResult(out, err)
}

// errSecItemNotFound, as `security` reports it in its exit status.
const secItemNotFound = 44

// keychainResult maps a `security find-generic-password` outcome. Only "item not found" means absent; any
// other failure (locked keychain, denied access, missing tool) is an error, never "no credential".
func keychainResult(out []byte, err error) ([]byte, error) {
	var ee *exec.ExitError
	switch {
	case err == nil:
		return base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	case errors.As(err, &ee) && ee.ExitCode() == secItemNotFound:
		return nil, nil
	}
	return nil, fmt.Errorf("the macOS Keychain could not be read: %w", err)
}

func (k *macKeychain) Set(b []byte) error {
	cmd := exec.Command("security", "-i")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("add-generic-password -U -s %s -a %s -w %s\n",
		quote(keychainService), quote(k.account), base64.StdEncoding.EncodeToString(b)))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil || strings.Contains(stderr.String(), "error") {
		return errors.New("the macOS Keychain refused the credential")
	}
	return nil
}

func (k *macKeychain) Delete() error {
	_ = exec.Command("security", "delete-generic-password", "-s", keychainService, "-a", k.account).Run()
	return nil
}

// secretService uses libsecret's `secret-tool`, which reads the secret from STDIN.
type secretService struct{ account string }

func (s *secretService) Name() string { return "Secret Service" }

func (s *secretService) Get() ([]byte, error) {
	cmd := exec.Command("secret-tool", "lookup", "service", keychainService, "account", s.account)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	return secretToolResult(out, stderr.Bytes(), err)
}

// secretToolResult maps a `secret-tool lookup` outcome. It exits 1 silently when nothing matches; a failure
// (no session bus, locked collection, missing tool) prints a diagnostic or fails otherwise — an error,
// never "no credential".
func secretToolResult(out, stderr []byte, err error) ([]byte, error) {
	var ee *exec.ExitError
	switch {
	case err == nil:
		return base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	case errors.As(err, &ee) && ee.ExitCode() == 1 && len(bytes.TrimSpace(out)) == 0 && len(bytes.TrimSpace(stderr)) == 0:
		return nil, nil
	}
	return nil, fmt.Errorf("the Secret Service could not be read: %w", err)
}

func (s *secretService) Set(b []byte) error {
	cmd := exec.Command("secret-tool", "store", "--label=Sigill for Claude Code", "service", keychainService, "account", s.account)
	cmd.Stdin = strings.NewReader(base64.StdEncoding.EncodeToString(b))
	return cmd.Run()
}

func (s *secretService) Delete() error {
	_ = exec.Command("secret-tool", "clear", "service", keychainService, "account", s.account).Run()
	return nil
}

// FileStore keeps the secret in a 0600 file inside the private plugin data directory,
// written atomically and never through a link.
type FileStore struct{ Path string }

func (f *FileStore) Name() string { return "private file" }

func (f *FileStore) Get() ([]byte, error) {
	fh, err := os.OpenFile(f.Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	fi, err := fh.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 || fi.Size() > 1<<20 {
		return nil, errors.New("the credential file is not a private regular file")
	}
	buf := make([]byte, fi.Size())
	_, err = fh.Read(buf)
	return buf, err
}

func (f *FileStore) Set(b []byte) error {
	dir := filepath.Dir(f.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".credential.tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(b)
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(name)
		return werr
	}
	if err := os.Rename(name, f.Path); err != nil {
		os.Remove(name)
		return err
	}
	// The rename is only durable once the directory entry is synced. This survives a process crash; across
	// a power loss it is as durable as the OS's fsync (on macOS fsync does not flush the drive's cache).
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (f *FileStore) Delete() error {
	if err := os.Remove(f.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// quote for `security -i`: our values contain no quotes or spaces, but be strict.
func quote(s string) string { return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"` }
