package auth

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// expire makes the stored access token due for refresh.
func expire(t *testing.T, m *Manager) {
	t.Helper()
	c, err := m.load()
	if err != nil || c == nil {
		t.Fatal("no credential")
	}
	c.AccessExpiry = time.Now().Add(-time.Minute)
	if err := m.save(c); err != nil {
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
	if c, _ := m.load(); c == nil || c.Uncertain == "" {
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
}

func (s *memStore) Name() string { return "mem" }
func (s *memStore) Get() ([]byte, error) {
	if s.failGet {
		return nil, nil
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

func newFallback(t *testing.T) (*fallback, *memStore) {
	dir := t.TempDir()
	mem := &memStore{}
	return &fallback{primary: mem, file: &FileStore{Path: filepath.Join(dir, "credential.json")}, marker: filepath.Join(dir, "credential.store")}, mem
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
