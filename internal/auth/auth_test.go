package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeAS is a minimal authorization server with rotating refresh tokens and reuse detection.
type fakeAS struct {
	srv          *httptest.Server
	mu           sync.Mutex
	refresh      string // the one live refresh token
	refreshCalls atomic.Int32
	revoked      bool
	dropRefresh  bool   // close the connection on refresh after reading it (lost answer)
	expiresIn    int    // access token lifetime in seconds
	grantScope   string // scope granted (default: what was asked)
	lastDevice   string
}

func (f *fakeAS) set(fn func()) { f.mu.Lock(); fn(); f.mu.Unlock() }

func (f *fakeAS) isRevoked() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.revoked }

func (f *fakeAS) device() string { f.mu.Lock(); defer f.mu.Unlock(); return f.lastDevice }

func jwt(tenant, sub string) string {
	p, _ := json.Marshal(map[string]any{"tenant_id": tenant, "sub": sub, "scope": Scope})
	return "eyJhbGciOiJIUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(p) + ".sig"
}

func newFakeAS(t *testing.T) *fakeAS {
	f := &fakeAS{expiresIn: 3600}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/oauth/authorize",
			"token_endpoint": f.srv.URL + "/oauth/token", "revocation_endpoint": f.srv.URL + "/oauth/revoke",
			"registration_endpoint": f.srv.URL + "/oauth/register",
		})
	})
	mux.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.mu.Lock()
		f.lastDevice = q.Get("device_id")
		f.mu.Unlock()
		if q.Get("code_challenge_method") != "S256" || q.Get("scope") != Scope || !strings.HasPrefix(q.Get("redirect_uri"), "http://127.0.0.1:") {
			http.Error(w, "bad request", 400)
			return
		}
		cb := q.Get("redirect_uri") + "?" + url.Values{"code": {"code-1"}, "state": {q.Get("state")}, "iss": {f.srv.URL}}.Encode()
		http.Redirect(w, r, cb, http.StatusFound)
	})
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		issue := func() {
			f.refresh = fmt.Sprintf("rt-%d", time.Now().UnixNano())
			scope := f.grantScope
			if scope == "" {
				scope = Scope
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": jwt("tenant-1", "user-1"), "token_type": "Bearer",
				"expires_in": f.expiresIn, "refresh_token": f.refresh, "scope": scope})
		}
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			issue()
		case "refresh_token":
			f.refreshCalls.Add(1)
			if f.revoked || r.Form.Get("refresh_token") != f.refresh {
				f.revoked = true // reuse detection: the whole grant dies
				w.WriteHeader(400)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
				return
			}
			if f.dropRefresh {
				f.refresh = "rt-spent" // the server rotated; the answer never arrives
				hj, _ := w.(http.Hijacker)
				conn, _, _ := hj.Hijack()
				conn.Close()
				return
			}
			issue()
		}
	})
	mux.HandleFunc("/oauth/revoke", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.revoked = true
		f.mu.Unlock()
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// follow plays the browser: it follows the authorize redirect to the loopback callback.
func follow(u string) error {
	resp, err := http.Get(u)
	if err == nil {
		resp.Body.Close()
	}
	return err
}

func newManager(t *testing.T) *Manager {
	dir := t.TempDir()
	return &Manager{Dir: dir, Store: &FileStore{Path: dir + "/credential.json"}, HTTP: &http.Client{Timeout: 5 * time.Second}}
}

func connect(t *testing.T, m *Manager, f *fakeAS) *Credential {
	t.Helper()
	var out bytes.Buffer
	cred, err := m.Connect(context.Background(), ConnectOptions{Issuer: f.srv.URL, ClientID: "test-client", OpenBrowser: follow, Out: &out, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return cred
}

func TestConnect_StoresAPinnedCredential(t *testing.T) {
	f := newFakeAS(t)
	m := newManager(t)
	cred := connect(t, m, f)
	if cred.TenantID != "tenant-1" || cred.Subject != "user-1" || cred.RefreshToken == "" {
		t.Fatalf("credential incomplete: %+v", cred)
	}
	if f.device() == "" || f.device() != cred.DeviceID {
		t.Fatal("the installation's device id must be sent and kept")
	}
	if tok, _, err := m.AccessToken(context.Background(), f.srv.URL); err != nil || tok == "" {
		t.Fatalf("access token: %v", err)
	}
	// Pinned: the credential is never offered to another server.
	if _, _, err := m.AccessToken(context.Background(), "https://evil.example"); err == nil {
		t.Fatal("a credential must not be sent to another issuer")
	}
	raw, _ := m.Store.Get()
	if strings.Contains(string(raw), "code-1") {
		t.Fatal("the authorization code must not be stored")
	}
}

func TestConnect_RefusesAGrantWithoutRecording(t *testing.T) {
	f := newFakeAS(t)
	f.set(func() { f.grantScope = "offline_access" })
	m := newManager(t)
	_, err := m.Connect(context.Background(), ConnectOptions{Issuer: f.srv.URL, ClientID: "c", OpenBrowser: follow, Out: &bytes.Buffer{}, Timeout: 5 * time.Second})
	if err == nil {
		t.Fatal("a connection without mcp:agent:record must not be stored")
	}
}

// Parallel hooks with an expiring token refresh exactly once: a second refresh with the
// rotated-away token would make the server revoke the whole grant.
func TestRefresh_ParallelHooksRefreshOnce(t *testing.T) {
	f := newFakeAS(t)
	f.set(func() { f.expiresIn = 60 }) // within the refresh margin: every hook wants to refresh
	m := newManager(t)
	connect(t, m, f)
	f.set(func() { f.expiresIn = 3600 })
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Separate managers on the same directory = separate hook processes.
			mm := &Manager{Dir: m.Dir, Store: &FileStore{Path: m.Dir + "/credential.json"}, HTTP: m.HTTP}
			if _, _, err := mm.AccessToken(context.Background(), f.srv.URL); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("hook failed: %v", err)
	}
	if n := f.refreshCalls.Load(); n != 1 {
		t.Fatalf("refresh requests = %d, want exactly 1", n)
	}
	if f.isRevoked() {
		t.Fatal("the grant must survive parallel hooks")
	}
}

// A refresh whose answer is lost may have been spent: never replay it — require a reconnect.
func TestRefresh_LostAnswerIsUncertain_NeverReplayed(t *testing.T) {
	f := newFakeAS(t)
	f.set(func() { f.expiresIn = 60 })
	m := newManager(t)
	connect(t, m, f)
	f.set(func() { f.dropRefresh = true })
	if _, _, err := m.AccessToken(context.Background(), f.srv.URL); err == nil {
		t.Fatal("a lost refresh answer must not yield a token")
	}
	f.set(func() { f.dropRefresh = false })
	before := f.refreshCalls.Load()
	if _, cred, err := m.AccessToken(context.Background(), f.srv.URL); err == nil || cred == nil || cred.Uncertain == "" {
		t.Fatalf("the credential must be marked uncertain (err %v)", err)
	}
	if f.refreshCalls.Load() != before {
		t.Fatal("an uncertain refresh token must never be sent again")
	}
	if f.isRevoked() {
		t.Fatal("nothing may have triggered reuse detection")
	}
}

func TestRefresh_RevokedGrantEndsTheConnection(t *testing.T) {
	f := newFakeAS(t)
	f.set(func() { f.expiresIn = 60 })
	m := newManager(t)
	connect(t, m, f)
	f.set(func() { f.revoked = true })
	_, cred, err := m.AccessToken(context.Background(), f.srv.URL)
	if err == nil || cred == nil || cred.RefreshToken != "" {
		t.Fatalf("a refused refresh must end the connection (err %v)", err)
	}
}

func TestCallback_WrongStateIsIgnored(t *testing.T) {
	f := newFakeAS(t)
	m := newManager(t)
	browser := func(u string) error {
		au, _ := url.Parse(u)
		redirect := au.Query().Get("redirect_uri")
		// A forged callback first: must be refused and must not end the wait.
		if resp, err := http.Get(redirect + "?code=evil&state=forged"); err == nil {
			resp.Body.Close()
			if resp.StatusCode != 400 {
				return fmt.Errorf("forged callback answered %d", resp.StatusCode)
			}
		}
		return follow(u)
	}
	cred, err := m.Connect(context.Background(), ConnectOptions{Issuer: f.srv.URL, ClientID: "c", OpenBrowser: browser, Out: &bytes.Buffer{}, Timeout: 5 * time.Second})
	if err != nil || cred == nil {
		t.Fatalf("the real callback must still complete the connect: %v", err)
	}
}

func TestDisconnect_RevokesAndForgets(t *testing.T) {
	f := newFakeAS(t)
	m := newManager(t)
	connect(t, m, f)
	if err := m.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !f.isRevoked() {
		t.Fatal("disconnect must revoke the grant")
	}
	if c, _ := m.Current(); c != nil {
		t.Fatal("disconnect must forget the credential")
	}
	if _, _, err := m.AccessToken(context.Background(), f.srv.URL); err != ErrNotConnected {
		t.Fatalf("want ErrNotConnected, got %v", err)
	}
}
