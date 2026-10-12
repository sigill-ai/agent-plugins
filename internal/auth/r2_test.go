package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// expire makes the stored access token due for refresh.
func expire(t *testing.T, m *Manager) {
	t.Helper()
	c, err := m.load(context.Background())
	if err != nil || c == nil {
		t.Fatal("no credential")
	}
	c.AccessExpiry = time.Now().Add(-time.Minute)
	if err := m.save(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

// R2-2: a process that died after the server rotated the refresh token (the marker is left, the new
// credential was never stored) must not replay the old token.
func TestRefresh_DeathAfterRotation_NeverReplays(t *testing.T) {
	f := newFakeAS(t)
	m := newManager(t)
	connect(t, m, f)
	expire(t, m)
	if err := m.markRefreshInFlight(); err != nil { // the dead process got this far, and the server rotated
		t.Fatal(err)
	}
	f.set(func() { f.refresh = "rt-rotated" })
	_, _, err := m.AccessToken(context.Background(), f.srv.URL)
	if err == nil {
		t.Fatal("an interrupted refresh must require a reconnect")
	}
	if n := f.refreshCalls.Load(); n != 0 || f.isRevoked() {
		t.Fatalf("the old refresh token was replayed (%d calls, revoked %v)", n, f.isRevoked())
	}
	if c, _ := m.load(context.Background()); c == nil || c.Uncertain == "" {
		t.Fatal("the credential must be marked uncertain")
	}
}

type failingSet struct {
	*FileStore
	fail bool
}

func (s *failingSet) Set(b []byte) error {
	if s.fail {
		return errors.New("disk full")
	}
	return s.FileStore.Set(b)
}

// R2-2: the server rotated, but the new credential could not be stored.
func TestRefresh_PersistenceFailure_NeverReplays(t *testing.T) {
	f := newFakeAS(t)
	m := newManager(t)
	store := &failingSet{FileStore: m.Store.(*FileStore)}
	m.Store = store
	connect(t, m, f)
	expire(t, m)
	store.fail = true
	if _, _, err := m.AccessToken(context.Background(), f.srv.URL); err == nil {
		t.Fatal("a refresh whose result cannot be stored must fail")
	}
	store.fail = false
	if _, _, err := m.AccessToken(context.Background(), f.srv.URL); err == nil {
		t.Fatal("the next hook must require a reconnect")
	}
	if n := f.refreshCalls.Load(); n != 1 || f.isRevoked() {
		t.Fatalf("refresh calls %d (want 1), revoked %v: the spent token was replayed", n, f.isRevoked())
	}
}

// A memory backend standing in for the keychain.
type memStore struct {
	val     []byte
	failSet bool
	failGet bool
	failDel bool
	onGet   func() // runs once, inside the next Get (interleavings)
}

func (s *memStore) Name() string { return "mem" }
func (s *memStore) Get() ([]byte, error) {
	if f := s.onGet; f != nil {
		s.onGet = nil
		f()
	}
	if s.failGet {
		return nil, errors.New("keychain locked")
	}
	return s.val, nil
}
func (s *memStore) Set(b []byte) error {
	if s.failSet {
		return errors.New("locked")
	}
	s.val = append([]byte(nil), b...)
	return nil
}
func (s *memStore) Delete() error {
	if s.failDel {
		return errors.New("locked")
	}
	s.val = nil
	return nil
}

func newFallback(t *testing.T) (*authority, *memStore) {
	dir := t.TempDir()
	mem := &memStore{}
	return &authority{primary: mem, osPrimary: "keychain", file: &FileStore{Path: filepath.Join(dir, "credential.json")}, marker: filepath.Join(dir, "credential.store")}, mem
}

// R2-3: keychain holds R0; the R1 write fails there and lands in the file; the keychain becomes readable
// again — R0 must never be read.
func TestFallback_NeverResurrectsASupersededSecret(t *testing.T) {
	fb, mem := newFallback(t)
	if err := fb.Set([]byte("R0")); err != nil {
		t.Fatal(err)
	}
	mem.failSet = true
	if err := fb.Set([]byte("R1")); err != nil {
		t.Fatal(err)
	}
	mem.failSet = false // readable again, still holding R0
	got, err := fb.Get()
	if err != nil || string(got) != "R1" {
		t.Fatalf("got %q, want R1", got)
	}
	var mk storeMarker
	raw, _ := os.ReadFile(fb.marker)
	json.Unmarshal(raw, &mk)
	if mk.Backend != "file" || mk.Generation != 2 {
		t.Fatalf("marker %+v", mk)
	}
	// Back to the keychain when it works again; the file copy is removed.
	if err := fb.Set([]byte("R2")); err != nil {
		t.Fatal(err)
	}
	if got, _ := fb.Get(); string(got) != "R2" {
		t.Fatalf("got %q, want R2", got)
	}
}

// R2-3: a disconnect whose keychain delete fails cannot be undone by a later read.
func TestFallback_DeleteTombstoneWins(t *testing.T) {
	fb, mem := newFallback(t)
	if err := fb.Set([]byte("R0")); err != nil {
		t.Fatal(err)
	}
	mem.failDel = true
	_ = fb.Delete()
	if got, err := fb.Get(); err != nil || got != nil {
		t.Fatalf("a disconnected store returned %q (%v)", got, err)
	}
}

// R3-3: every invocation builds its own store (as every hook process does), and which backends are usable
// changes between invocations. The marker alone decides; a backend that is not usable now is reported,
// never substituted by a leftover elsewhere.
func TestAuthority_AcrossInvocationsAndModeSwitches(t *testing.T) {
	dir := t.TempDir()
	mem := &memStore{}
	gui := func() *authority { // keychain usable
		return &authority{primary: mem, osPrimary: "keychain", file: &FileStore{Path: filepath.Join(dir, "credential.json")}, marker: filepath.Join(dir, "credential.store")}
	}
	headless := func() *authority { // same machine, keychain not usable in this invocation
		return &authority{osPrimary: "keychain", file: &FileStore{Path: filepath.Join(dir, "credential.json")}, marker: filepath.Join(dir, "credential.store")}
	}
	if err := gui().Set([]byte("R0")); err != nil {
		t.Fatal(err)
	}
	// A leftover file from some earlier headless run must not be read while the keychain is authoritative.
	os.WriteFile(filepath.Join(dir, "credential.json"), []byte("STALE"), 0o600)
	if _, err := headless().Get(); err == nil || !strings.Contains(err.Error(), "not available") {
		t.Fatalf("headless read of a keychain-held credential must refuse, got %v", err)
	}
	// A headless connect makes the file authoritative; back in the GUI the file is what is read.
	if err := headless().Set([]byte("R1")); err != nil {
		t.Fatal(err)
	}
	if got, err := gui().Get(); err != nil || string(got) != "R1" {
		t.Fatalf("got %q (%v), want R1", got, err)
	}
	// Disconnect in one mode, read in the other: nothing.
	if err := gui().Delete(); err != nil {
		t.Fatal(err)
	}
	if got, err := headless().Get(); err != nil || got != nil {
		t.Fatalf("after disconnect got %q (%v)", got, err)
	}
}

// R3-3: stores written before markers existed are used only when unambiguous, and adopted (marker written)
// only by Migrate.
func TestAuthority_LegacyStatesAreNeverGuessed(t *testing.T) {
	mk := func(primary SecretStore, readOnly bool, dir string) *authority {
		return &authority{primary: primary, osPrimary: "keychain", readOnlyPrimary: readOnly,
			file: &FileStore{Path: filepath.Join(dir, "credential.json")}, marker: filepath.Join(dir, "credential.store")}
	}
	// R0 in the keychain, a newer R1 in the file (0.1/0.2.0 fell back to the file when the keychain failed).
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "credential.json"), []byte("R1"), 0o600)
	if _, err := mk(&memStore{val: []byte("R0")}, false, dir).Get(); !errors.Is(err, ErrCredentialAmbiguous) {
		t.Fatalf("two different legacy secrets must be ambiguous, got %v", err)
	}
	// Only a file, but the keychain this OS may have used cannot be read now: ambiguous too.
	dir = t.TempDir()
	os.WriteFile(filepath.Join(dir, "credential.json"), []byte("R1"), 0o600)
	if _, err := mk(nil, false, dir).Get(); !errors.Is(err, ErrCredentialAmbiguous) {
		t.Fatalf("an unreadable keychain must make a legacy file ambiguous, got %v", err)
	}
	// File-only by choice is no proof either; a keychain read that finds nothing is.
	if _, err := mk(nil, true, dir).Get(); !errors.Is(err, ErrCredentialAmbiguous) {
		t.Fatalf("file-only mode must not adopt a legacy file it cannot rule out, got %v", err)
	}
	a := mk(&memStore{}, true, dir)
	if got, err := a.Get(); err != nil || string(got) != "R1" {
		t.Fatalf("file with a provably empty keychain got %q (%v)", got, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "credential.store")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an ordinary Get never writes the marker")
	}
	if err := a.Migrate(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "credential.store"))
	if !strings.Contains(string(raw), `"file"`) {
		t.Fatalf("marker %s", raw)
	}
	// Only the keychain holds it: used, adopted by Migrate, and the same in the next invocation.
	dir = t.TempDir()
	mem := &memStore{val: []byte("R2")}
	if got, err := mk(mem, false, dir).Get(); err != nil || string(got) != "R2" {
		t.Fatalf("keychain legacy read got %q (%v)", got, err)
	}
	if err := mk(mem, false, dir).Migrate(); err != nil {
		t.Fatal(err)
	}
	if got, err := mk(mem, false, dir).Get(); err != nil || string(got) != "R2" {
		t.Fatalf("next invocation got %q (%v)", got, err)
	}
	// A 0.2.1–0.2.2 marker ("primary") still means this OS's store.
	dir = t.TempDir()
	os.WriteFile(filepath.Join(dir, "credential.store"), []byte(`{"backend":"primary","generation":3}`), 0o600)
	if got, err := mk(&memStore{val: []byte("R3")}, false, dir).Get(); err != nil || string(got) != "R3" {
		t.Fatalf("legacy marker got %q (%v)", got, err)
	}
}

// R3-3 at the Manager: an ambiguous store is reported with the reconnect hint, never used.
func TestManager_AmbiguousStore_RequiresReconnect(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "credential.json"), []byte(`{"issuer":"https://x"}`), 0o600)
	m := &Manager{Dir: dir, Store: &authority{osPrimary: "keychain", file: &FileStore{Path: filepath.Join(dir, "credential.json")},
		marker: filepath.Join(dir, "credential.store")}}
	_, _, err := m.AccessToken(context.Background(), "https://x")
	if err == nil || !strings.Contains(err.Error(), "/sigill:connect") || !strings.Contains(err.Error(), "unambiguously") {
		t.Fatalf("got %v", err)
	}
}

// R3-6: if the in-flight marker cannot be made durable, the refresh token is never sent.
func TestRefresh_NotSentWhenTheMarkerCannotBeMadeDurable(t *testing.T) {
	sent := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sent = true; w.WriteHeader(500) }))
	defer srv.Close()
	dir := t.TempDir()
	m := &Manager{Dir: dir, Store: &FileStore{Path: filepath.Join(dir, "credential.json")}, HTTP: srv.Client()}
	cred := &Credential{Issuer: srv.URL, TokenURL: srv.URL + "/token", ClientID: "c", RefreshToken: "R0", AccessToken: "a",
		AccessExpiry: time.Now().Add(-time.Minute)}
	if err := m.save(context.Background(), cred); err != nil {
		t.Fatal(err)
	}
	// The marker's place is taken by a directory: it cannot be written.
	os.Mkdir(m.inFlightPath(), 0o700)
	if _, _, err := m.AccessToken(context.Background(), srv.URL); err == nil {
		t.Fatal("the refresh must not proceed")
	}
	if sent {
		t.Fatal("the refresh token left the machine without a durable in-flight marker")
	}
}
