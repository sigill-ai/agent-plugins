// Package state keeps recorded runs between hook invocations.
//
// Every hook is a separate process and Claude Code runs hooks for parallel tool
// calls concurrently, so a session's state is only read and written under an
// exclusive flock(2) lock, which the kernel releases if a hook dies.
//
// Layout (all private to the user, 0700/0600):
//
//	<root>/sessions/<key>/lock                one lock per Claude Code session
//	<root>/sessions/<key>/current             name of the session's current run
//	<root>/sessions/<key>/runs/<run>/          one immutable directory per run
//	    state.json, ctrl.json, 0000-run_start.json, …, outbox/<artifact>
//
// <key> is a hash of the session id, so distinct ids never share a directory.
// A run directory is never reused: a resumed, closed session starts a new run.
package state

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/sigill-ai/claude-plugins/internal/evidence"
)

// Run is the persisted chain state of one recorded run. It never holds content:
// pending inputs are kept as digests only.
type Run struct {
	SessionID     string `json:"sessionId"`
	Name          string `json:"name"` // run directory name
	CorrelationID string `json:"correlationId"`
	CertificateID string `json:"certificateId,omitempty"` // fixed for the whole run: one run, one signer
	Qualified     bool   `json:"qualified,omitempty"`     // qualified timestamps for this run (fixed at start)
	// Account that started the run (issuer|tenant|user, or the API key's fingerprint). A run is
	// never continued, finalized or delivered under another account or organisation.
	Account      string                   `json:"account,omitempty"`
	AgentID      string                   `json:"agentId"`
	AgentVersion string                   `json:"agentVersion"`
	ControlSig   string                   `json:"controlSignatureSha256"`
	NextSeq      int                      `json:"nextSeq"`
	PrevSig      string                   `json:"prevSignatureSha256"`
	Policy       evidence.TimestampPolicy `json:"timestampPolicy"`
	Closed       bool                     `json:"closed"`
	Broken       string                   `json:"broken,omitempty"`
	// Pending is written durably BEFORE an artifact is requested from the sealing
	// service. After a crash it decides recovery: a stored artifact matching it is
	// committed; anything else stops the run — a seq is never issued twice.
	Pending        *Pending          `json:"pending,omitempty"`
	CloseRequested string            `json:"closeRequested,omitempty"` // session ended; run_end still to be sealed
	PendingInputs  []evidence.Object `json:"pendingInputs,omitempty"`
	URIs           map[string]string `json:"uris"` // uri → digest; one URI, one content (§5)
	StartedAt      time.Time         `json:"startedAt"`
	SegmentOf      string            `json:"segmentOf,omitempty"` // previous run's correlationId when the event limit split a session

	// SchemaVersion of the run's execution artifacts: "2" (Agent Delegation v1) for runs started by
	// this version; "" means "1" (runs started before). One run never mixes versions.
	SchemaVersion string `json:"schemaVersion,omitempty"`
	// A sub-agent run (agent-delegation-v1.md): the parent's correlationId and delegation signature its
	// run_start binds, the parent run's directory, and the Claude Code agent_id whose hooks it records.
	ParentCorrelationID string `json:"parentCorrelationId,omitempty"`
	ParentDelegationSig string `json:"parentDelegationSignatureSha256,omitempty"`
	ParentRun           string `json:"parentRun,omitempty"`
	ClaudeAgentID       string `json:"claudeAgentId,omitempty"`
	// Delegations this run sealed. Each intent is saved with the Pending of the event that commits it,
	// so after a crash the chain head (NextSeq) decides what was sealed: never two results for one child.
	Delegations []Delegation `json:"delegations,omitempty"`
	// PairingStopped: Claude Code contradicted a sub-agent pairing this session; no further sub-agent is bound.
	PairingStopped bool `json:"pairingStopped,omitempty"`
	// FidelityIssue records a known capture-fidelity problem of this run (e.g. a contradicted sub-agent
	// pairing). Such a run never closes "completed": it closes "aborted" with this as its detail.
	FidelityIssue string `json:"fidelityIssue,omitempty"`
	// Resumes counts the times a resumed session continued this run. A close request carries the epoch it
	// was made in, so a session end read before a resume never closes the resumed run.
	Resumes int `json:"resumes,omitempty"`
}

// Delegation is one sub-agent this run started.
type Delegation struct {
	ChildCorrelationID string    `json:"childCorrelationId"`
	ChildAgentID       string    `json:"childAgentId"`
	SubagentType       string    `json:"subagentType"`
	UseID              string    `json:"useId,omitempty"`
	Seq                int       `json:"seq"`           // the delegation event
	Sig                string    `json:"sig,omitempty"` // its signatureSha256, once committed
	ChildRun           string    `json:"childRun,omitempty"`
	ClaudeAgentID      string    `json:"claudeAgentId,omitempty"`
	ResultSeq          int       `json:"resultSeq"` // the delegation_result event; -1 none
	CreatedAt          time.Time `json:"createdAt"`
}

// Committed: the delegation event is part of the chain.
func (d Delegation) Committed(r *Run) bool { return d.Seq < r.NextSeq && d.Sig != "" }

// Resolved: its delegation_result is part of the chain.
func (d Delegation) Resolved(r *Run) bool { return d.ResultSeq >= 0 && d.ResultSeq < r.NextSeq }

// Outstanding counts committed delegations without a committed result.
func (r *Run) Outstanding() int {
	n := 0
	for _, d := range r.Delegations {
		if d.Committed(r) && !d.Resolved(r) {
			n++
		}
	}
	return n
}

// Version is the run's execution schemaVersion.
func (r *Run) Version() string {
	if r.SchemaVersion == "" {
		return "1"
	}
	return r.SchemaVersion
}

// Pending identifies the one artifact being sealed.
type Pending struct {
	Name         string `json:"name"`
	Seq          int    `json:"seq"` // -1 for the control artifact
	EnvelopeHash string `json:"envelopeHash"`
	Close        bool   `json:"close,omitempty"` // committing it closes the run (run_end)
	// Queue: the artifact is to be delivered to the index. Recorded before sealing, so recovery recreates
	// a delivery marker that a crash between the artifact and its marker would otherwise lose.
	Queue bool `json:"queue,omitempty"`
}

// Artifact is one sealed artifact in AgentRunBundle form (common rules §7).
type Artifact struct {
	Envelope      json.RawMessage   `json:"envelope"`
	Signature     json.RawMessage   `json:"signature"`
	ObjectDigests map[string]string `json:"objectDigests"`
}

type Store struct{ Dir string }

// SessionKey maps a session id to its directory name, collision-free.
func SessionKey(session string) string {
	h := sha256.Sum256([]byte(session))
	return hex.EncodeToString(h[:16])
}

func (s Store) sessionDir(session string) string {
	return filepath.Join(s.Dir, "sessions", SessionKey(session))
}

// RunPath is the path of a file in the run's directory.
func (s Store) RunPath(r *Run, elem ...string) string { return s.runPath(r, elem...) }

func (s Store) runPath(r *Run, elem ...string) string {
	return filepath.Join(append([]string{s.sessionDir(r.SessionID), "runs", r.Name}, elem...)...)
}

// ensureRoot creates the storage root or checks an existing one: a real directory
// (not a symlink), owned by this user, not accessible to others. Arbitrary code
// running as the same user is outside what any local store can protect against.
func (s Store) ensureRoot() error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	return checkPrivateDir(s.Dir, true)
}

func checkPrivateDir(p string, fixMode bool) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", p)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is not owned by the current user", p)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		if !fixMode {
			return fmt.Errorf("%s is accessible to other users", p)
		}
		if err := os.Chmod(p, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// mkdirPrivate creates each missing component below base as a 0700 directory and
// refuses existing components that are symlinks or not private.
func mkdirPrivate(base string, rel ...string) (string, error) {
	p := base
	for _, c := range rel {
		p = filepath.Join(p, c)
		if err := os.Mkdir(p, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return "", err
		}
		if err := checkPrivateDir(p, false); err != nil {
			return "", err
		}
	}
	return p, nil
}

// writeAtomic replaces dir/name with data: a fresh exclusive temp file (never an
// existing path or link), fsync, rename.
func writeAtomic(dir, name string, data []byte) error {
	f, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(tmp)
		return werr
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// readRegular reads a file this store wrote, refusing links and non-regular files.
func readRegular(p string, max int64) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > max {
		return nil, fmt.Errorf("%s is not a regular file within %d bytes", filepath.Base(p), max)
	}
	buf := make([]byte, fi.Size())
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// WithLock runs fn while holding the session's lock, waiting at most until ctx ends.
func (s Store) WithLock(ctx context.Context, session string, fn func() error) error {
	if err := s.ensureRoot(); err != nil {
		return err
	}
	dir, err := mkdirPrivate(s.Dir, "sessions", SessionKey(session))
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for the session lock")
		case <-time.After(20 * time.Millisecond):
		}
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}

// Current loads the session's current run, or nil when there is none.
func (s Store) Current(session string) (*Run, error) {
	raw, err := readRegular(filepath.Join(s.sessionDir(session), "current"), 256)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.LoadRun(session, strings.TrimSpace(string(raw)))
}

// LoadRun loads one run of a session by its directory name.
func (s Store) LoadRun(session, name string) (*Run, error) {
	if name == "" || name != filepath.Base(name) || strings.HasPrefix(name, ".") {
		return nil, fmt.Errorf("invalid run name")
	}
	raw, err := readRegular(filepath.Join(s.sessionDir(session), "runs", name, "state.json"), 4<<20)
	if err != nil {
		return nil, err
	}
	var r Run
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	if r.SessionID != session || r.Name != name {
		return nil, fmt.Errorf("run state does not belong to this session")
	}
	return &r, nil
}

// CurrentForKey loads the current run of the session stored under key (used by
// sweeps, which only know keys). The run must really belong to that key.
func (s Store) CurrentForKey(key string) (*Run, error) {
	if key != filepath.Base(key) || strings.HasPrefix(key, ".") {
		return nil, fmt.Errorf("invalid session key")
	}
	raw, err := readRegular(filepath.Join(s.Dir, "sessions", key, "current"), 256)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(string(raw))
	if name == "" || name != filepath.Base(name) || strings.HasPrefix(name, ".") {
		return nil, fmt.Errorf("invalid run name")
	}
	st, err := readRegular(filepath.Join(s.Dir, "sessions", key, "runs", name, "state.json"), 4<<20)
	if err != nil {
		return nil, err
	}
	var r Run
	if err := json.Unmarshal(st, &r); err != nil {
		return nil, err
	}
	if SessionKey(r.SessionID) != key || r.Name != name {
		return nil, fmt.Errorf("run state does not belong to this session")
	}
	return &r, nil
}

// RunsForKey loads every run of the session stored under key (status, sweeps); runs that do not
// verifiably belong to that key are skipped.
func (s Store) RunsForKey(key string) []*Run {
	if key != filepath.Base(key) || strings.HasPrefix(key, ".") {
		return nil
	}
	entries, _ := os.ReadDir(filepath.Join(s.Dir, "sessions", key, "runs"))
	runs := []*Run{}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		st, err := readRegular(filepath.Join(s.Dir, "sessions", key, "runs", e.Name(), "state.json"), 4<<20)
		if err != nil {
			continue
		}
		var r Run
		if json.Unmarshal(st, &r) != nil || SessionKey(r.SessionID) != key || r.Name != e.Name() {
			continue
		}
		runs = append(runs, &r)
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].Name < runs[j].Name })
	return runs
}

// CloseRequest is a session end recorded WITHOUT the session lock (SessionEnd must not wait for a lock a
// sealing hook may hold longer than Claude Code lets SessionEnd live). It names the run that was current
// and that run's resume epoch; the finalizer, a sweep or the next hook applies it under the lock.
//
// Every request is its own immutable file, named after its run plus a random suffix: a producer never
// replaces a request, and a consumer removes exactly the requests it read (File), never one published after.
type CloseRequest struct {
	Run     string    `json:"run"`
	Resumes int       `json:"resumes"` // the run's Resumes when the session ended; an older epoch is stale
	Reason  string    `json:"reason"`
	At      time.Time `json:"at"`
	File    string    `json:"-"`
}

const closeRequestDir = "close-requests"

// validRunName: a run name that is safe as a path element and in a close-request file name.
func validRunName(name string) bool {
	return name != "" && name == filepath.Base(name) && !strings.HasPrefix(name, ".") && !strings.Contains(name, ".")
}

// RequestClose durably records that the session ended on run at resume epoch resumes (atomic, no lock).
func (s Store) RequestClose(session, run string, resumes int, reason string) error {
	if !validRunName(run) {
		return fmt.Errorf("invalid run name %q", run)
	}
	if err := s.ensureRoot(); err != nil {
		return err
	}
	dir, err := mkdirPrivate(s.Dir, "sessions", SessionKey(session), closeRequestDir)
	if err != nil {
		return err
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	raw, _ := json.Marshal(CloseRequest{Run: run, Resumes: resumes, Reason: reason, At: time.Now().UTC()})
	if err := writeAtomic(dir, run+"."+hex.EncodeToString(nonce[:]), raw); err != nil {
		return err
	}
	return syncDir(dir)
}

// closeRequestsIn lists the requests in dir, oldest first; for one run when run != "".
func closeRequestsIn(dir, run string) []*CloseRequest {
	entries, _ := os.ReadDir(dir)
	reqs := []*CloseRequest{}
	for _, e := range entries {
		name, nonce, ok := strings.Cut(e.Name(), ".")
		if !ok || !validRunName(name) || len(nonce) != 16 || strings.Contains(nonce, ".") || (run != "" && name != run) {
			continue // temp files start with "."; anything else is not a request
		}
		p := filepath.Join(dir, e.Name())
		raw, err := readRegular(p, 4096)
		if err != nil {
			continue
		}
		var c CloseRequest
		if json.Unmarshal(raw, &c) != nil || c.Run != name {
			continue
		}
		c.File = p
		reqs = append(reqs, &c)
	}
	sort.Slice(reqs, func(i, j int) bool { return reqs[i].At.Before(reqs[j].At) })
	return reqs
}

// CloseRequestsFor reads the session's unapplied close requests for run, oldest first.
func (s Store) CloseRequestsFor(session, run string) []*CloseRequest {
	if !validRunName(run) {
		return nil
	}
	return closeRequestsIn(filepath.Join(s.sessionDir(session), closeRequestDir), run)
}

// PendingCloseRuns lists the runs of the session that have unapplied close requests.
func (s Store) PendingCloseRuns(session string) []string {
	return pendingRuns(filepath.Join(s.sessionDir(session), closeRequestDir))
}

// PendingCloseRunsForKey: PendingCloseRuns for the session stored under key (sweeps, status).
func (s Store) PendingCloseRunsForKey(key string) []string {
	if key != filepath.Base(key) || strings.HasPrefix(key, ".") {
		return nil
	}
	return pendingRuns(filepath.Join(s.Dir, "sessions", key, closeRequestDir))
}

func pendingRuns(dir string) []string {
	seen := map[string]bool{}
	names := []string{}
	for _, c := range closeRequestsIn(dir, "") {
		if !seen[c.Run] {
			seen[c.Run] = true
			names = append(names, c.Run)
		}
	}
	sort.Strings(names)
	return names
}

// CloseRequestedForKey reports whether the session stored under key has an unapplied close request.
func (s Store) CloseRequestedForKey(key string) bool { return len(s.PendingCloseRunsForKey(key)) > 0 }

// ClearCloseRequest removes exactly this request, once applied (or found stale). A request published
// after it was read is a different file and stays.
func (s Store) ClearCloseRequest(req *CloseRequest) {
	if req == nil || req.File == "" {
		return
	}
	_ = os.Remove(req.File)
}

// syncDir makes a rename in dir durable across a machine crash (the file data itself is synced first).
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Runs lists the session's run names, oldest first.
func (s Store) Runs(session string) []string {
	entries, _ := os.ReadDir(filepath.Join(s.sessionDir(session), "runs"))
	names := []string{}
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names
}

// Sessions lists the keys of all recorded sessions.
func (s Store) SessionKeys() []string {
	entries, _ := os.ReadDir(filepath.Join(s.Dir, "sessions"))
	keys := []string{}
	for _, e := range entries {
		if e.IsDir() {
			keys = append(keys, e.Name())
		}
	}
	return keys
}

// NewRun creates the run's directory, writes its first state and makes it the
// session's current run. r.Name must be fresh.
func (s Store) NewRun(r *Run) error {
	if err := s.newRunDir(r); err != nil {
		return err
	}
	return writeAtomic(s.sessionDir(r.SessionID), "current", []byte(r.Name))
}

// NewChildRun creates a sub-agent run's directory and first state. The session's current run
// (the main thread) is unchanged. r.Name must be fresh.
func (s Store) NewChildRun(r *Run) error { return s.newRunDir(r) }

func (s Store) newRunDir(r *Run) error {
	if _, err := mkdirPrivate(s.Dir, "sessions", SessionKey(r.SessionID), "runs"); err != nil {
		return err
	}
	dir := filepath.Join(s.sessionDir(r.SessionID), "runs", r.Name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err // never reuse a run directory
	}
	return s.Save(r)
}

// Save atomically replaces the run's state.
func (s Store) Save(r *Run) error {
	raw, _ := json.MarshalIndent(r, "", "  ")
	return writeAtomic(s.runPath(r), "state.json", raw)
}

// SaveArtifact atomically stores a sealed artifact and, when queue is set, marks it
// for index delivery. Both happen before the chain head that includes it is
// committed, so recovery after a crash finds a complete artifact or none.
func (s Store) SaveArtifact(r *Run, name string, a Artifact, queue bool) error {
	raw, _ := json.Marshal(a)
	if err := writeAtomic(s.runPath(r), name+".json", raw); err != nil {
		return err
	}
	if !queue {
		return nil
	}
	return s.Enqueue(r, name)
}

// Enqueue marks a stored artifact for index delivery. Idempotent.
func (s Store) Enqueue(r *Run, name string) error {
	if name == "" || name != filepath.Base(name) || strings.HasPrefix(name, ".") {
		return fmt.Errorf("invalid artifact name")
	}
	dir, err := mkdirPrivate(s.runPath(r), "outbox")
	if err != nil {
		return err
	}
	return writeAtomic(dir, name, nil)
}

// LoadArtifact reads one stored artifact by name.
func (s Store) LoadArtifact(r *Run, name string) (Artifact, error) {
	var a Artifact
	if name == "" || name != filepath.Base(name) || strings.HasPrefix(name, ".") {
		return a, fmt.Errorf("invalid artifact name")
	}
	raw, err := readRegular(s.runPath(r, name+".json"), 16<<20)
	if err != nil {
		return a, err
	}
	return a, json.Unmarshal(raw, &a)
}

// ArtifactNames lists the run's stored artifacts: the control artifact first, then
// events in sequence order.
func (s Store) ArtifactNames(r *Run) []string {
	entries, _ := os.ReadDir(s.runPath(r))
	names := []string{}
	for _, e := range entries {
		n := e.Name()
		if e.Type().IsRegular() && strings.HasSuffix(n, ".json") && n != "state.json" && !strings.HasPrefix(n, ".") {
			names = append(names, strings.TrimSuffix(n, ".json"))
		}
	}
	return ctrlFirst(names)
}

// Pending lists the run's artifacts awaiting index delivery, the control artifact first.
func (s Store) PendingDelivery(r *Run) []string {
	entries, _ := os.ReadDir(s.runPath(r, "outbox"))
	names := []string{}
	for _, e := range entries {
		if e.Type().IsRegular() && !strings.HasPrefix(e.Name(), ".") {
			names = append(names, e.Name())
		}
	}
	return ctrlFirst(names)
}

// Delivered removes an artifact from the run's outbox. A concurrent remove is harmless.
func (s Store) Delivered(r *Run, name string) {
	if name == filepath.Base(name) && !strings.HasPrefix(name, ".") {
		_ = os.Remove(s.runPath(r, "outbox", name))
	}
}

func ctrlFirst(names []string) []string {
	sort.SliceStable(names, func(i, j int) bool {
		if (names[i] == "ctrl") != (names[j] == "ctrl") {
			return names[i] == "ctrl"
		}
		return names[i] < names[j]
	})
	return names
}

// AppendLog appends one line to the plugin log without following links.
func (s Store) AppendLog(line string) {
	if s.ensureRoot() != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(s.Dir, "sigill-hook.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Mode().IsRegular() {
		fmt.Fprintln(f, line)
	}
}

// OldestPendingAge is how long the run's oldest undelivered artifact has waited.
func (s Store) OldestPendingAge(r *Run) time.Duration {
	entries, _ := os.ReadDir(s.runPath(r, "outbox"))
	oldest := time.Duration(0)
	for _, e := range entries {
		if fi, err := e.Info(); err == nil {
			if age := time.Since(fi.ModTime()); age > oldest {
				oldest = age
			}
		}
	}
	return oldest
}

// Once reports true at most once per interval for name (a marker file's age).
func (s Store) Once(name string, every time.Duration) bool {
	if s.ensureRoot() != nil {
		return false
	}
	p := filepath.Join(s.Dir, "."+name)
	if fi, err := os.Lstat(p); err == nil && time.Since(fi.ModTime()) < every {
		return false
	}
	return writeAtomic(s.Dir, "."+name, []byte(time.Now().UTC().Format(time.RFC3339))) == nil
}
