package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// lockedPrimary is an OS store whose helper works but whose keychain is locked (Codex round 4 repro).
type lockedPrimary struct{}

func (*lockedPrimary) Name() string         { return "locked keychain" }
func (*lockedPrimary) Get() ([]byte, error) { return nil, errors.New("keychain locked") }
func (*lockedPrimary) Set([]byte) error     { return errors.New("keychain locked") }
func (*lockedPrimary) Delete() error        { return errors.New("keychain locked") }

func authorityIn(dir string, primary SecretStore, readOnly bool) *authority {
	return &authority{primary: primary, osPrimary: "keychain", readOnlyPrimary: readOnly,
		file: &FileStore{Path: filepath.Join(dir, "credential.json")}, marker: filepath.Join(dir, "credential.store")}
}

func markerOf(t *testing.T, a *authority) storeMarker {
	t.Helper()
	var m storeMarker
	raw, err := os.ReadFile(a.marker)
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(raw, &m)
	return m
}

// R4-2 (Codex round 4 repro, ported): an available helper on a locked keychain must not let an older
// legacy file be selected.
func TestAuthority_LegacyPrimaryReadFailure_NeverAdoptsTheFile(t *testing.T) {
	dir := t.TempDir()
	a := authorityIn(dir, &lockedPrimary{}, false)
	if err := a.file.Set([]byte("older R0")); err != nil {
		t.Fatal(err)
	}
	got, err := a.Get()
	if err == nil || got != nil {
		t.Fatalf("unreadable primary must not select old file: got=%q err=%v", got, err)
	}
	if !errors.Is(err, ErrCredentialAmbiguous) {
		t.Fatalf("want ErrCredentialAmbiguous, got %v", err)
	}
	if err := a.Migrate(); err == nil {
		t.Fatal("Migrate must not adopt it either")
	}
	if _, err := os.Stat(a.marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("no marker may be written for an uncertain store")
	}
}

// R4-2: a read failure of the backend the marker names is an error, never "not connected".
func TestAuthority_MarkedBackendReadFailure_IsAnError(t *testing.T) {
	dir := t.TempDir()
	mem := &memStore{}
	a := authorityIn(dir, mem, false)
	if err := a.Set([]byte("R0")); err != nil {
		t.Fatal(err)
	}
	mem.failGet = true
	if got, err := a.Get(); err == nil || got != nil {
		t.Fatalf("got %q, %v: a locked keychain is not an absent credential", got, err)
	}
	m := &Manager{Dir: dir, Store: a}
	if _, _, err := m.AccessToken(context.Background(), "https://x"); err == nil || errors.Is(err, ErrNotConnected) ||
		!strings.Contains(err.Error(), "/sigill:connect") {
		t.Fatalf("got %v", err)
	}
}

// R4-2: SIGILL_CREDENTIAL_STORE=file selects where new secrets go; it is no proof that a pre-marker file is
// the newest credential.
func TestAuthority_ForcedFileMode_LegacyFileStaysAmbiguous(t *testing.T) {
	for name, primary := range map[string]SecretStore{
		"keychain locked":           &lockedPrimary{},
		"keychain holds another":    &memStore{val: []byte("R1")},
		"keychain not readable now": nil,
	} {
		dir := t.TempDir()
		a := authorityIn(dir, primary, true)
		os.WriteFile(a.file.Path, []byte("R0"), 0o600)
		if _, err := a.Get(); !errors.Is(err, ErrCredentialAmbiguous) {
			t.Fatalf("%s: got %v", name, err)
		}
	}
}

// R4-2: the OS store an installation could have used does not depend on its helper being on PATH: when
// the helper disappears, a legacy file is still uncertain, and nothing is adopted.
func TestDefaultStore_HelperDisappearance_KeepsTheAmbiguity(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("no OS credential store on " + runtime.GOOS)
	}
	t.Setenv("PATH", t.TempDir()) // neither security nor secret-tool
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	for _, mode := range []string{"", "file"} {
		t.Setenv("SIGILL_CREDENTIAL_STORE", mode)
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "credential.json"), []byte("R0"), 0o600)
		s := DefaultStore(dir)
		if _, err := s.Get(); !errors.Is(err, ErrCredentialAmbiguous) {
			t.Fatalf("mode %q: got %v", mode, err)
		}
		if err := s.(*authority).Migrate(); err == nil {
			t.Fatalf("mode %q: migrated an uncertain store", mode)
		}
		// New secrets still go to the file and become authoritative there.
		if err := s.Set([]byte("R1")); err != nil {
			t.Fatal(err)
		}
		if got, err := s.Get(); err != nil || string(got) != "R1" {
			t.Fatalf("mode %q: got %q (%v)", mode, got, err)
		}
	}
}

// R4-2: an ordinary Get racing a writer never writes a marker, so it cannot overwrite the writer's.
func TestAuthority_GetRacingASet_NeverOverwritesTheMarker(t *testing.T) {
	dir := t.TempDir()
	mem := &memStore{}
	a := authorityIn(dir, mem, false)
	os.WriteFile(a.file.Path, []byte("R-old"), 0o600)
	// While Get is reading the legacy state, a refresh stores R-new (another process).
	mem.onGet = func() {
		if err := authorityIn(dir, mem, false).Set([]byte("R-new")); err != nil {
			t.Error(err)
		}
	}
	_, _ = a.Get()
	if m := markerOf(t, a); m.Backend != "keychain" || m.Generation != 1 {
		t.Fatalf("marker %+v: the reader overwrote the writer's marker", m)
	}
	if got, err := a.Get(); err != nil || string(got) != "R-new" {
		t.Fatalf("got %q (%v), want R-new", got, err)
	}
}

// R4-2: migration runs under the credential lock, so a writer holding it is never overtaken by a
// migration decided on a stale read; Migrate with a marker present does nothing.
func TestManager_MigrationRacingAMarkerChange(t *testing.T) {
	dir := t.TempDir()
	mem := &memStore{}
	os.WriteFile(filepath.Join(dir, "credential.json"),
		[]byte(`{"issuer":"https://x","refreshToken":"R-old","accessExpiry":"2000-01-01T00:00:00Z"}`), 0o600)
	m := &Manager{Dir: dir, Store: authorityIn(dir, mem, false)}
	writer := &Manager{Dir: dir, Store: authorityIn(dir, mem, false)}

	inside, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- writer.withLock(context.Background(), func() error {
			close(inside)
			<-release
			return writer.save(context.Background(), &Credential{Issuer: "https://x", RefreshToken: "R-new", Uncertain: "test"})
		})
	}()
	<-inside
	migrated := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _, _ = m.AccessToken(ctx, "https://x") // due for refresh: migrates under the lock
		close(migrated)
	}()
	select {
	case <-migrated:
		t.Fatal("a migration ran while another writer held the credential lock")
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	<-migrated
	a := m.Store.(*authority)
	if mk := markerOf(t, a); mk.Backend != "keychain" || mk.Generation != 1 {
		t.Fatalf("marker %+v: overwritten by a stale migration", mk)
	}
	if err := a.Migrate(); err != nil {
		t.Fatal(err)
	}
	if mk := markerOf(t, a); mk.Backend != "keychain" || mk.Generation != 1 {
		t.Fatalf("Migrate rewrote an existing marker: %+v", mk)
	}
	if c, err := m.Current(); err != nil || c == nil || c.RefreshToken != "R-new" {
		t.Fatalf("current %+v (%v)", c, err)
	}
}

// R4-2: the helpers' "nothing stored" answers are told apart from failures.
func TestBackends_AbsenceIsNotFailure(t *testing.T) {
	exit := func(code int, stderr string) error {
		return exec.Command("sh", "-c", fmt.Sprintf("printf %%s '%s' >&2; exit %d", stderr, code)).Run()
	}
	if b, err := keychainResult(nil, exit(44, "")); err != nil || b != nil {
		t.Fatalf("errSecItemNotFound: %q %v", b, err)
	}
	for _, code := range []int{36, 51, 1} { // locked, user interaction not allowed, other
		if _, err := keychainResult(nil, exit(code, "")); err == nil {
			t.Fatalf("security exit %d must be an error", code)
		}
	}
	if _, err := keychainResult(nil, exec.ErrNotFound); err == nil {
		t.Fatal("a missing security tool must be an error")
	}
	if b, err := secretToolResult(nil, nil, exit(1, "")); err != nil || b != nil {
		t.Fatalf("no match: %q %v", b, err)
	}
	if _, err := secretToolResult(nil, []byte("secret-tool: Cannot autolaunch D-Bus"), exit(1, "x")); err == nil {
		t.Fatal("a D-Bus failure must be an error")
	}
	if _, err := secretToolResult(nil, nil, exec.ErrNotFound); err == nil {
		t.Fatal("a missing secret-tool must be an error")
	}
}
