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

// DefaultStore picks the OS keychain when it is usable and a private file otherwise.
// SIGILL_CREDENTIAL_STORE=file forces the file (headless machines, tests).
func DefaultStore(dir string) SecretStore {
	file := &FileStore{Path: filepath.Join(dir, "credential.json")}
	if os.Getenv("SIGILL_CREDENTIAL_STORE") == "file" {
		return file
	}
	account := "default:" + dir // one credential per plugin data directory
	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("security"); err == nil {
			return &fallback{primary: &macKeychain{account: account}, file: file, marker: filepath.Join(dir, "credential.store")}
		}
	case "linux":
		if _, err := exec.LookPath("secret-tool"); err == nil && os.Getenv("DBUS_SESSION_BUS_ADDRESS") != "" {
			return &fallback{primary: &secretService{account: account}, file: file, marker: filepath.Join(dir, "credential.store")}
		}
	}
	return file
}

// fallback uses the keychain and falls back to the private file when the keychain fails (locked, no
// session). Exactly one backend is authoritative at a time, named by a durable private marker
// ("primary", "file", or "none" after a disconnect): Get reads only that backend, so a superseded
// secret left in the other one (e.g. a spent refresh token in a keychain that was briefly
// unavailable) can never be read again. Set writes the new secret first, then flips the marker; a
// crash in between leaves the previous, consistent state (and the refresh protocol's in-flight
// marker makes that state uncertain, never replayed). Delete writes the tombstone first.
type fallback struct {
	primary SecretStore
	file    *FileStore
	marker  string
}

type storeMarker struct {
	Backend    string `json:"backend"` // primary | file | none
	Generation int    `json:"generation"`
}

func (f *fallback) Name() string { return f.primary.Name() + " (file fallback)" }

func (f *fallback) readMarker() (*storeMarker, error) {
	raw, err := (&FileStore{Path: f.marker}).Get()
	if err != nil || len(raw) == 0 {
		return nil, err
	}
	var m storeMarker
	if err := json.Unmarshal(raw, &m); err != nil || (m.Backend != "primary" && m.Backend != "file" && m.Backend != "none") {
		return nil, errors.New("the credential store marker is unreadable")
	}
	return &m, nil
}

func (f *fallback) writeMarker(backend string, generation int) error {
	raw, _ := json.Marshal(storeMarker{Backend: backend, Generation: generation})
	return (&FileStore{Path: f.marker}).Set(raw)
}

func (f *fallback) Get() ([]byte, error) {
	m, err := f.readMarker()
	if err != nil {
		return nil, err
	}
	switch {
	case m == nil:
		// Written before markers existed: the keychain first, as then. The next Set adds a marker.
		if b, err := f.primary.Get(); err == nil && len(b) > 0 {
			return b, nil
		}
		return f.file.Get()
	case m.Backend == "primary":
		return f.primary.Get()
	case m.Backend == "file":
		return f.file.Get()
	default:
		return nil, nil // disconnected
	}
}

func (f *fallback) Set(b []byte) error {
	gen := 0
	if m, err := f.readMarker(); err == nil && m != nil {
		gen = m.Generation
	}
	backend := "primary"
	if err := f.primary.Set(b); err != nil {
		if err := f.file.Set(b); err != nil {
			return err
		}
		backend = "file"
	}
	if err := f.writeMarker(backend, gen+1); err != nil {
		return err
	}
	if backend == "primary" {
		_ = f.file.Delete() // the superseded copy, no longer readable anyway
	}
	return nil
}

func (f *fallback) Delete() error {
	gen := 0
	if m, err := f.readMarker(); err == nil && m != nil {
		gen = m.Generation
	}
	if err := f.writeMarker("none", gen+1); err != nil { // the tombstone first: nothing can be resurrected
		return err
	}
	_ = f.primary.Delete()
	return f.file.Delete()
}

// macKeychain uses `security`. The secret is written through `security -i` on STDIN, so it
// never appears in a process argument list; base64 keeps the interactive parser simple.
type macKeychain struct{ account string }

func (k *macKeychain) Name() string { return "macOS Keychain" }

func (k *macKeychain) Get() ([]byte, error) {
	out, err := exec.Command("security", "find-generic-password", "-s", keychainService, "-a", k.account, "-w").Output()
	if err != nil {
		return nil, nil // not found (or locked): no credential here
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
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
	out, err := exec.Command("secret-tool", "lookup", "service", keychainService, "account", s.account).Output()
	if err != nil || len(out) == 0 {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
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
	return os.Rename(name, f.Path)
}

func (f *FileStore) Delete() error {
	if err := os.Remove(f.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// quote for `security -i`: our values contain no quotes or spaces, but be strict.
func quote(s string) string { return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"` }
