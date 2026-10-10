package auth

import (
	"bytes"
	"encoding/base64"
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
			return &fallback{primary: &macKeychain{account: account}, file: file}
		}
	case "linux":
		if _, err := exec.LookPath("secret-tool"); err == nil && os.Getenv("DBUS_SESSION_BUS_ADDRESS") != "" {
			return &fallback{primary: &secretService{account: account}, file: file}
		}
	}
	return file
}

// fallback uses the keychain and falls back to the private file if the keychain fails
// (locked, no session). Whatever is written last is read first.
type fallback struct {
	primary SecretStore
	file    *FileStore
}

func (f *fallback) Name() string { return f.primary.Name() + " (file fallback)" }

func (f *fallback) Get() ([]byte, error) {
	if b, err := f.primary.Get(); err == nil && len(b) > 0 {
		return b, nil
	}
	return f.file.Get()
}

func (f *fallback) Set(b []byte) error {
	if err := f.primary.Set(b); err == nil {
		_ = f.file.Delete()
		return nil
	}
	return f.file.Set(b)
}

func (f *fallback) Delete() error {
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
