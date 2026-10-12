// Package auth connects the recorder to Sigill with Sigill sign-in (OAuth 2.1 authorization
// code + PKCE, RFC 8252 loopback redirect) and keeps the resulting credential.
//
// Rules this package keeps:
//   - The issuer is pinned with the credential. A credential is only ever sent to the
//     issuer it was obtained from, whatever SIGILL_API_URL says later.
//   - Refresh tokens rotate and Sigill revokes a grant when an old one is replayed, so
//     refreshes happen under one cross-session lock, are persisted before the lock is
//     released, and a refresh whose outcome is unknown is never retried: the credential
//     is marked uncertain and the user reconnects.
//   - Background hooks never open a browser; only `sigill-hook connect` does.
//   - Secrets go to the OS keychain (macOS Keychain, Secret Service) when available, else
//     to a private file. They never appear in process arguments, logs or status output.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const (
	// Scope requested by the recorder: agent recording + refresh, nothing else.
	Scope = "mcp:agent:record offline_access"
	// defaultClientID is Sigill's published client metadata document (CIMD) for Claude Code; a host sets
	// its own with SetHost.
	defaultClientID = "https://sigill.ai/.well-known/oauth-client/claude-code.json"
	// refreshMargin: refresh an access token that expires within this window.
	refreshMargin = 5 * time.Minute
)

// Credential is what a connect produces. Stored as one secret.
type Credential struct {
	Issuer       string    `json:"issuer"`
	ClientID     string    `json:"clientId"`
	DeviceID     string    `json:"deviceId"`
	TokenURL     string    `json:"tokenUrl"`
	RevokeURL    string    `json:"revokeUrl,omitempty"`
	AccessToken  string    `json:"accessToken"`
	AccessExpiry time.Time `json:"accessExpiry"`
	RefreshToken string    `json:"refreshToken,omitempty"`
	Scope        string    `json:"scope"`
	TenantID     string    `json:"tenantId"`
	Subject      string    `json:"subject"`
	// Uncertain: a refresh was sent and its answer lost. The old refresh token may be
	// spent; replaying it would revoke the grant. Requires a reconnect.
	Uncertain   string    `json:"uncertain,omitempty"`
	ConnectedAt time.Time `json:"connectedAt"`
}

// Account identifies who records: issuer + organisation + user.
func (c *Credential) Account() string { return c.Issuer + "|" + c.TenantID + "|" + c.Subject }

// ErrNotConnected: no usable credential; the user must run `sigill-hook connect`.
var ErrNotConnected = errors.New("not connected to Sigill")

// Manager owns the credential for one plugin data directory.
type Manager struct {
	Dir   string // private plugin data root
	Store SecretStore
	HTTP  *http.Client
}

func New(dir string) *Manager {
	return &Manager{Dir: dir, Store: DefaultStore(dir), HTTP: &http.Client{Timeout: 20 * time.Second}}
}

// ── Discovery ──────────────────────────────────────────────────────────────

type metadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
	RegistrationEndpoint  string `json:"registration_endpoint"`
}

func (m *Manager) discover(ctx context.Context, issuer string) (*metadata, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/oauth-authorization-server", nil)
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach %s: %w", issuer, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s does not offer Sigill sign-in (%d)", issuer, resp.StatusCode)
	}
	var md metadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&md); err != nil {
		return nil, fmt.Errorf("authorization server metadata: %w", err)
	}
	// RFC 8414 §3.3: the metadata's issuer must be the one we asked.
	if strings.TrimRight(md.Issuer, "/") != issuer {
		return nil, fmt.Errorf("authorization server metadata names another issuer")
	}
	for _, u := range []string{md.AuthorizationEndpoint, md.TokenEndpoint} {
		if !sameOrigin(u, issuer) {
			return nil, fmt.Errorf("authorization server endpoints are not on %s", issuer)
		}
	}
	return &md, nil
}

func sameOrigin(u, issuer string) bool {
	a, err1 := url.Parse(u)
	b, err2 := url.Parse(issuer)
	return err1 == nil && err2 == nil && a.Scheme == b.Scheme && a.Host == b.Host
}

// The host the recorder runs in: its name on the sign-in page and in the client registration, the command
// a user runs to (re)connect, and its client metadata document.
var (
	HostName        = "Claude Code"
	ConnectCommand  = "/sigill:connect"
	DefaultClientID = defaultClientID
)

// SetHost names the host for user-facing text and selects its OAuth client.
func SetHost(name, connectCommand, clientID string) {
	HostName, ConnectCommand, DefaultClientID = name, connectCommand, clientID
}

// ── Connect (interactive) ──────────────────────────────────────────────────

// ConnectOptions configure an interactive connect.
type ConnectOptions struct {
	Issuer      string // e.g. https://api.sigill.ai
	ClientID    string // CIMD URL; empty → DefaultClientID
	UseDCR      bool   // register a client dynamically (servers without our CIMD host)
	OpenBrowser func(string) error
	Out         io.Writer     // where the sign-in URL and progress go
	Timeout     time.Duration // how long to wait for the browser
}

// Connect runs the authorization code flow with a loopback redirect and stores the
// credential. It replaces any previous credential of this installation.
func (m *Manager) Connect(ctx context.Context, o ConnectOptions) (*Credential, error) {
	issuer := strings.TrimRight(o.Issuer, "/")
	md, err := m.discover(ctx, issuer)
	if err != nil {
		return nil, err
	}
	// Bind the listener BEFORE opening the browser (RFC 8252 §7.3), on 127.0.0.1 only.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", ln.Addr().(*net.TCPAddr).Port)

	clientID := o.ClientID
	if clientID == "" {
		clientID = DefaultClientID
	}
	if o.UseDCR {
		if clientID, err = m.register(ctx, md, issuer); err != nil {
			return nil, err
		}
	}
	device, err := m.DeviceID()
	if err != nil {
		return nil, err
	}
	verifier := randomToken(48)
	challenge := b64(sha256Sum([]byte(verifier)))
	state := randomToken(24)
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {state},
		"scope": {Scope}, "resource": {issuer + "/mcp"},
		"device_id": {device}, "device_label": {deviceLabel()},
	}
	authURL := md.AuthorizationEndpoint + "?" + q.Encode()

	type result struct {
		code string
		err  error
	}
	done := make(chan result, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		cq := r.URL.Query()
		var res result
		switch {
		case cq.Get("state") != state:
			http.Error(w, "This sign-in does not belong to the running connect. Start again.", http.StatusBadRequest)
			return // not ours: keep waiting for the real callback
		case cq.Get("iss") != "" && strings.TrimRight(cq.Get("iss"), "/") != issuer: // RFC 9207
			res.err = errors.New("the sign-in answer came from another issuer")
		case cq.Get("error") != "":
			res.err = fmt.Errorf("sign-in was not completed (%s)", cq.Get("error"))
		case cq.Get("code") == "":
			res.err = errors.New("the sign-in answer carried no code")
		default:
			res.code = cq.Get("code")
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if res.err != nil {
			fmt.Fprint(w, page("Sigill was not connected", "You can close this tab and run "+ConnectCommand+" again."))
		} else {
			fmt.Fprint(w, page(HostName+" is connected to Sigill", "You can close this tab and return to "+HostName+"."))
		}
		select {
		case done <- res:
		default: // a duplicate callback: the first one wins
		}
	})}
	go srv.Serve(ln)
	defer srv.Close()

	fmt.Fprintf(o.Out, "Opening your browser to sign in to Sigill. If it does not open, visit:\n\n  %s\n\n", authURL)
	if o.OpenBrowser != nil {
		_ = o.OpenBrowser(authURL)
	}
	timeout := o.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	var res result
	select {
	case res = <-done:
	case <-time.After(timeout):
		return nil, errors.New("timed out waiting for the browser sign-in")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if res.err != nil {
		return nil, res.err
	}

	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {res.code}, "redirect_uri": {redirect},
		"code_verifier": {verifier}, "client_id": {clientID}, "resource": {issuer + "/mcp"},
	}
	tok, err := m.tokenRequest(ctx, md.TokenEndpoint, form)
	if err != nil {
		return nil, err
	}
	cred := &Credential{
		Issuer: issuer, ClientID: clientID, DeviceID: device, TokenURL: md.TokenEndpoint, RevokeURL: md.RevocationEndpoint,
		ConnectedAt: time.Now().UTC(),
	}
	if err := cred.apply(tok); err != nil {
		return nil, err
	}
	if !strings.Contains(" "+cred.Scope+" ", " mcp:agent:record ") {
		return nil, errors.New("the connection was approved without agent recording; connect again and approve it")
	}
	err = m.withLock(ctx, func() error {
		old, _ := m.load(ctx)
		if old != nil && old.RefreshToken != "" && old.RevokeURL != "" {
			m.revoke(ctx, old) // best effort: the replaced connection ends
		}
		if err := m.save(ctx, cred); err != nil {
			return err
		}
		m.clearRefreshInFlight() // a new grant: an interrupted refresh of the old one no longer matters
		return nil
	})
	return cred, err
}

func (m *Manager) register(ctx context.Context, md *metadata, issuer string) (string, error) {
	if md.RegistrationEndpoint == "" || !sameOrigin(md.RegistrationEndpoint, issuer) {
		return "", errors.New("the server does not offer client registration")
	}
	body, _ := json.Marshal(map[string]any{
		"client_name": "Sigill for " + HostName, "redirect_uris": []string{"http://127.0.0.1/callback"},
		"grant_types": []string{"authorization_code", "refresh_token"}, "token_endpoint_auth_method": "none",
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, md.RegistrationEndpoint, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var r struct {
		ClientID string `json:"client_id"`
	}
	if resp.StatusCode != 201 || json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&r) != nil || r.ClientID == "" {
		return "", fmt.Errorf("client registration failed (%d)", resp.StatusCode)
	}
	return r.ClientID, nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	Error        string `json:"error"`
}

// errNotSent: the request never left this machine (connection refused, DNS) — safe to retry.
type errNotSent struct{ err error }

func (e errNotSent) Error() string { return e.err.Error() }

func (m *Manager) tokenRequest(ctx context.Context, endpoint string, form url.Values) (*tokenResponse, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := m.HTTP.Do(req)
	if err != nil {
		var op *net.OpError
		if errors.As(err, &op) && op.Op == "dial" {
			return nil, errNotSent{err}
		}
		return nil, err
	}
	defer resp.Body.Close()
	var t tokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&t); err != nil {
		return nil, fmt.Errorf("token response: %w", err)
	}
	if resp.StatusCode != 200 || t.AccessToken == "" {
		if t.Error == "" {
			t.Error = fmt.Sprintf("http %d", resp.StatusCode)
		}
		return &t, fmt.Errorf("token request refused (%s)", t.Error)
	}
	return &t, nil
}

// apply copies a token response into the credential and reads the identity claims.
func (c *Credential) apply(t *tokenResponse) error {
	claims, err := jwtClaims(t.AccessToken)
	if err != nil {
		return err
	}
	tenant, _ := claims["tenant_id"].(string)
	sub, _ := claims["sub"].(string)
	if tenant == "" || sub == "" {
		return errors.New("the access token names no organisation")
	}
	if c.TenantID != "" && (c.TenantID != tenant || c.Subject != sub) {
		return errors.New("the refreshed token belongs to another account")
	}
	c.TenantID, c.Subject = tenant, sub
	c.AccessToken = t.AccessToken
	c.AccessExpiry = time.Now().Add(time.Duration(max(t.ExpiresIn, 60)) * time.Second).UTC()
	if t.RefreshToken != "" {
		c.RefreshToken = t.RefreshToken
	}
	if t.Scope != "" {
		c.Scope = t.Scope
	}
	return nil
}

// ── Access tokens for hooks (non-interactive) ──────────────────────────────

// AccessToken returns a valid access token for issuer, refreshing it if needed. It never
// prompts; ErrNotConnected means the user must connect.
func (m *Manager) AccessToken(ctx context.Context, issuer string) (string, *Credential, error) {
	issuer = strings.TrimRight(issuer, "/")
	cred, err := m.load(ctx)
	if err != nil {
		// An ambiguous or unavailable store is never guessed at: the user reconnects.
		return "", nil, fmt.Errorf("%v — run %s", err, ConnectCommand)
	}
	if cred == nil {
		return "", nil, ErrNotConnected
	}
	if cred.Issuer != issuer {
		// Pinned: never send this credential to another server.
		return "", nil, fmt.Errorf("connected to %s, not %s — run %s for this server", cred.Issuer, issuer, ConnectCommand)
	}
	if cred.Uncertain != "" {
		return "", cred, fmt.Errorf("the Sigill connection needs to be renewed (%s) — run %s", cred.Uncertain, ConnectCommand)
	}
	if time.Until(cred.AccessExpiry) > refreshMargin {
		return cred.AccessToken, cred, nil
	}
	err = m.withLock(ctx, func() error {
		if err := m.migrate(ctx); err != nil {
			return err
		}
		cur, err := m.load(ctx) // another hook may have refreshed meanwhile
		if err != nil || cur == nil {
			return ErrNotConnected
		}
		cred = cur
		// Under the lock no other refresh is running: a marker left behind means one was interrupted.
		if m.refreshInFlight() && cred.Uncertain == "" {
			cred.Uncertain = "a token refresh was interrupted"
			return m.save(ctx, cred)
		}
		if time.Until(cred.AccessExpiry) > refreshMargin || cred.Uncertain != "" {
			return nil
		}
		if cred.RefreshToken == "" {
			return ErrNotConnected
		}
		// The in-flight marker is durable BEFORE the refresh token leaves: if this process dies after the
		// server rotated it, or the new credential cannot be stored, the old token is never replayed.
		if err := m.markRefreshInFlight(); err != nil {
			return err
		}
		t, err := m.tokenRequest(ctx, cred.TokenURL, url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {cred.RefreshToken}, "client_id": {cred.ClientID},
			"resource": {cred.Issuer + "/mcp"},
		})
		var notSent errNotSent
		switch {
		case err == nil:
			if aerr := cred.apply(t); aerr != nil {
				cred.Uncertain = aerr.Error()
			}
		case errors.As(err, &notSent):
			m.clearRefreshInFlight() // the request never left this machine: nothing was spent
			return err
		case t != nil && (t.Error == "invalid_grant" || t.Error == "invalid_client" || t.Error == "unauthorized_client"):
			cred.RefreshToken = "" // refused: the grant is gone (revoked, expired, replaced)
			cred.Uncertain = "the connection was ended (" + t.Error + ")"
		case t != nil && t.Error == "http 429":
			m.clearRefreshInFlight() // throttled before processing: nothing was spent
			return err
		default:
			cred.Uncertain = "a token refresh got no answer"
		}
		if err := m.save(ctx, cred); err != nil {
			return err // the marker stays: the next hook requires a reconnect instead of replaying
		}
		m.clearRefreshInFlight()
		return nil
	})
	if err != nil {
		return "", cred, err
	}
	if cred.Uncertain != "" {
		return "", cred, fmt.Errorf("the Sigill connection needs to be renewed (%s) — run %s", cred.Uncertain, ConnectCommand)
	}
	return cred.AccessToken, cred, nil
}

// Disconnect revokes the grant (best effort) and forgets the credential.
func (m *Manager) Disconnect(ctx context.Context) error {
	return m.withLock(ctx, func() error {
		cred, _ := m.load(ctx)
		if cred != nil {
			m.revoke(ctx, cred)
		}
		if err := m.storeFor(ctx).Delete(); err != nil {
			return err
		}
		m.clearRefreshInFlight()
		return nil
	})
}

// Current returns the stored credential without refreshing (for status).
// Bounded by helperTimeout per OS-helper call.
func (m *Manager) Current() (*Credential, error) { return m.load(context.Background()) }

func (m *Manager) revoke(ctx context.Context, c *Credential) {
	if c.RevokeURL == "" || !sameOrigin(c.RevokeURL, c.Issuer) {
		return
	}
	tok := c.RefreshToken
	if tok == "" {
		tok = c.AccessToken
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.RevokeURL, strings.NewReader(url.Values{"token": {tok}, "client_id": {c.ClientID}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if resp, err := m.HTTP.Do(req); err == nil {
		resp.Body.Close()
	}
}

// storeFor binds the credential store to the caller's context: every read, migration, write and cleanup
// of one operation ends within the caller's deadline (Codex round 6).
func (m *Manager) storeFor(ctx context.Context) SecretStore {
	if b, ok := m.Store.(contextBinder); ok {
		return b.withContext(ctx)
	}
	return m.Store
}

func (m *Manager) load(ctx context.Context) (*Credential, error) {
	raw, err := m.storeFor(ctx).Get()
	if err != nil || len(raw) == 0 {
		return nil, err
	}
	var c Credential
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// migrate adopts an unambiguous pre-marker store (see authority.Migrate). Only under the credential lock.
func (m *Manager) migrate(ctx context.Context) error {
	if mg, ok := m.storeFor(ctx).(interface{ Migrate() error }); ok {
		return mg.Migrate()
	}
	return nil
}

func (m *Manager) inFlightPath() string { return filepath.Join(m.Dir, "refresh.inflight") }

func (m *Manager) refreshInFlight() bool {
	_, err := os.Lstat(m.inFlightPath())
	return err == nil
}

// markRefreshInFlight durably records that a refresh token is about to be sent.
func (m *Manager) markRefreshInFlight() error {
	if err := os.MkdirAll(m.Dir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(m.inFlightPath(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(time.Now().UTC().Format(time.RFC3339))
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	// The directory entry too: if that cannot be made durable, the refresh token is not sent.
	return syncDir(m.Dir)
}

func (m *Manager) clearRefreshInFlight() { _ = os.Remove(m.inFlightPath()) }

func (m *Manager) save(ctx context.Context, c *Credential) error {
	raw, _ := json.Marshal(c)
	return m.storeFor(ctx).Set(raw)
}

// withLock serializes credential reads/refreshes/writes across every hook process of
// this installation. Never taken while a session lock is held (hooks refresh first).
func (m *Manager) withLock(ctx context.Context, fn func() error) error {
	if err := os.MkdirAll(m.Dir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(m.Dir, "credential.lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	for {
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			break
		} else if !errors.Is(err, syscall.EWOULDBLOCK) {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.New("timed out waiting for the credential lock")
		case <-time.After(25 * time.Millisecond):
		}
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}

// DeviceID is a random, stable identifier of this installation (never derived from the
// machine), so each device keeps its own connection.
func (m *Manager) DeviceID() (string, error) {
	p := filepath.Join(m.Dir, "device-id")
	if raw, err := os.ReadFile(p); err == nil && len(strings.TrimSpace(string(raw))) >= 16 {
		return strings.TrimSpace(string(raw)), nil
	}
	if err := os.MkdirAll(m.Dir, 0o700); err != nil {
		return "", err
	}
	id := "dev-" + randomHex(16)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		if raw, rerr := os.ReadFile(p); rerr == nil {
			return strings.TrimSpace(string(raw)), nil // a concurrent first run won
		}
		return "", err
	}
	defer f.Close()
	_, err = f.WriteString(id)
	return id, err
}

// deviceLabel is coarse on purpose: OS and architecture, never the hostname.
func deviceLabel() string {
	osName := map[string]string{"darwin": "macOS", "linux": "Linux", "windows": "Windows"}[runtime.GOOS]
	if osName == "" {
		osName = runtime.GOOS
	}
	return osName + " " + runtime.GOARCH
}

// OpenBrowser opens url with the platform's opener; the URL is passed as one argument.
func OpenBrowser(u string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", u).Start()
	default:
		return exec.Command("xdg-open", u).Start()
	}
}

func jwtClaims(tok string) (map[string]any, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("the access token is not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var c map[string]any
	return c, json.Unmarshal(raw, &c)
}

func page(title, text string) string {
	return "<!doctype html><meta charset=utf-8><title>" + title + "</title><body style=\"font-family:system-ui;margin:4rem auto;max-width:32rem\"><h2>" +
		title + "</h2><p>" + text + "</p></body>"
}

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b64(b)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}
