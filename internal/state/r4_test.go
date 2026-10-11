package state

import "testing"

// R4-1 (Codex round 4 repro, ported): a consumer reads a close request; a producer publishes newer requests
// (for another run, and again for the same run) before the consumer acknowledges. The consumer removes
// exactly what it read: every newer request survives, each for the run it names.
func TestCloseRequest_OldConsumerNewProducer_KeepsTheNewerRequests(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if err := s.RequestClose("session", "old-run", 0, "old end"); err != nil {
		t.Fatal(err)
	}
	read := s.CloseRequestsFor("session", "old-run")
	if len(read) != 1 || read[0].Run != "old-run" {
		t.Fatalf("missing original request: %+v", read)
	}
	// Producers publish after the consumer read, before it removes what it read.
	if err := s.RequestClose("session", "new-run", 0, "new end"); err != nil {
		t.Fatal(err)
	}
	if err := s.RequestClose("session", "old-run", 1, "after resume"); err != nil {
		t.Fatal(err)
	}
	for _, q := range read {
		s.ClearCloseRequest(q)
	}
	if fresh := s.CloseRequestsFor("session", "new-run"); len(fresh) != 1 || fresh[0].Reason != "new end" {
		t.Fatalf("old consumer deleted newer close request: %+v", fresh)
	}
	if again := s.CloseRequestsFor("session", "old-run"); len(again) != 1 || again[0].Reason != "after resume" || again[0].Resumes != 1 {
		t.Fatalf("old consumer deleted a newer request for its own run: %+v", again)
	}
	if got := s.PendingCloseRuns("session"); len(got) != 2 {
		t.Fatalf("pending runs %v", got)
	}
}

func TestCloseRequest_RejectsUnsafeRunNames(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	for _, name := range []string{"", ".", "..", "../x", "a/b", ".hidden", "a.b"} {
		if err := s.RequestClose("session", name, 0, "x"); err == nil {
			t.Fatalf("run name %q accepted", name)
		}
	}
}
