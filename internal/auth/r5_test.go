package auth

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// stalledHelper installs a fake OS credential helper that never answers and keeps its stdout open from a
// background child — the shape that would hang an unbounded Output() (Codex round 5, supplemental P2).
func stalledHelper(t *testing.T, bin *string) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "helper")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 30 &\nsleep 30\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	old, oldTimeout := *bin, helperTimeout
	*bin, helperTimeout = script, 300*time.Millisecond
	t.Cleanup(func() { *bin, helperTimeout = old, oldTimeout })
}

func within(t *testing.T, limit time.Duration, what string, fn func()) {
	t.Helper()
	start := time.Now()
	fn()
	if d := time.Since(start); d > limit {
		t.Fatalf("%s took %s, want under %s", what, d, limit)
	}
}

func TestR5StalledKeychainHelperIsBoundedAndNeverAbsent(t *testing.T) {
	stalledHelper(t, &securityBin)
	k := &macKeychain{account: "test"}
	within(t, 3*time.Second, "keychain Get", func() {
		b, err := k.Get()
		if err == nil || b != nil {
			t.Fatalf("a stalled helper must be a failure, never absent: b=%v err=%v", b, err)
		}
	})
	within(t, 3*time.Second, "keychain Set", func() {
		if err := k.Set([]byte("secret")); err == nil {
			t.Fatal("a stalled helper must not report a successful write")
		}
	})
	within(t, 3*time.Second, "keychain Delete", func() { _ = k.Delete() })
}

func TestR5StalledSecretServiceHelperIsBoundedAndNeverAbsent(t *testing.T) {
	stalledHelper(t, &secretToolBin)
	s := &secretService{account: "test"}
	within(t, 3*time.Second, "secret-service Get", func() {
		b, err := s.Get()
		if err == nil || b != nil {
			t.Fatalf("a stalled helper must be a failure, never absent: b=%v err=%v", b, err)
		}
	})
	within(t, 3*time.Second, "secret-service Set", func() {
		if err := s.Set([]byte("secret")); err == nil {
			t.Fatal("a stalled helper must not report a successful write")
		}
	})
}

// The authority keeps its semantics when the helper stalls: a credential the marker places in the keychain
// is unreadable (an error), and a write falls back to the private file within the deadline.
func TestR5StalledHelperPreservesAuthoritySemantics(t *testing.T) {
	stalledHelper(t, &securityBin)
	dir := t.TempDir()
	a := authorityIn(dir, &macKeychain{account: "test"}, false)
	if err := a.writeMarker("keychain", 3); err != nil {
		t.Fatal(err)
	}
	within(t, 3*time.Second, "authority Get", func() {
		if b, err := a.Get(); err == nil || b != nil {
			t.Fatalf("the authoritative keychain cannot be read: want an error, got b=%v err=%v", b, err)
		}
	})
	within(t, 5*time.Second, "authority Set", func() {
		if err := a.Set([]byte(`{"v":1}`)); err != nil {
			t.Fatal(err)
		}
	})
	if m := markerOf(t, a); m.Backend != "file" || m.Generation != 4 {
		t.Fatalf("marker after a fallback write = %+v, want file/4", m)
	}
	within(t, 3*time.Second, "migration", func() {
		if err := a.Migrate(); err != nil {
			t.Fatal(err)
		}
	})
}

// A FIFO (or any special file) planted at the credential or marker path must neither block the reader nor
// be taken as "no credential".
func TestR5NonRegularCredentialFileIsRejectedWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"credential.json", "credential.store"} {
		if err := syscall.Mkfifo(filepath.Join(dir, name), 0o600); err != nil {
			t.Skipf("mkfifo unavailable: %v", err)
		}
	}
	f := &FileStore{Path: filepath.Join(dir, "credential.json")}
	within(t, 2*time.Second, "FileStore.Get on a FIFO", func() {
		if b, err := f.Get(); err == nil || b != nil {
			t.Fatalf("a FIFO must be rejected: b=%v err=%v", b, err)
		}
	})
	a := authorityIn(dir, nil, true)
	within(t, 2*time.Second, "authority Get with a FIFO marker", func() {
		if b, err := a.Get(); err == nil || b != nil {
			t.Fatalf("an unreadable marker must be an error, never absent: b=%v err=%v", b, err)
		}
	})
}

// Every credential operation honours the caller's deadline, not only helperTimeout: a hook with 50 ms left
// must not wait for an unrelated helper bound (Codex round 6, TestCodexAccessTokenHonorsCallerDeadline).
func TestR6AccessTokenHonorsCallerDeadline(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "helper")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexec sleep 30\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	oldBin, oldTimeout := securityBin, helperTimeout
	securityBin, helperTimeout = script, 800*time.Millisecond
	t.Cleanup(func() { securityBin, helperTimeout = oldBin, oldTimeout })
	a := authorityIn(dir, &macKeychain{account: "review"}, false)
	if err := a.writeMarker("keychain", 1); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Dir: dir, Store: a}
	for _, op := range []struct {
		name string
		fn   func(context.Context) error
	}{
		{"AccessToken", func(ctx context.Context) error {
			_, _, err := m.AccessToken(ctx, "https://example.invalid")
			return err
		}},
		{"save", func(ctx context.Context) error { return m.save(ctx, &Credential{Issuer: "https://example.invalid"}) }},
		{"Disconnect", func(ctx context.Context) error { return m.Disconnect(ctx) }},
	} {
		if err := a.writeMarker("keychain", 1); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		start := time.Now()
		err := op.fn(ctx)
		cancel()
		if d := time.Since(start); d > 350*time.Millisecond {
			t.Fatalf("%s: caller deadline 50ms ignored, took %s", op.name, d)
		}
		if op.name == "AccessToken" && err == nil {
			t.Fatal("a stalled credential read must fail")
		}
	}
}
