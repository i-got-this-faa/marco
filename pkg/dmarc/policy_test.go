package dmarc

import (
	"testing"

	msgauthdmarc "github.com/emersion/go-msgauth/dmarc"
)

func TestEvaluatePassSPFAligned(t *testing.T) {
	p := NewPolicy()

	policy, reason, err := p.Evaluate("example.com", "example.com", true, "other.com", false)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if policy != msgauthdmarc.PolicyNone {
		t.Errorf("expected PolicyNone, got %q", policy)
	}
	if reason != "pass" {
		t.Errorf("expected reason 'pass', got %q", reason)
	}
}

func TestEvaluatePassDKIMAligned(t *testing.T) {
	p := NewPolicy()

	policy, reason, err := p.Evaluate("example.com", "other.com", false, "example.com", true)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if policy != msgauthdmarc.PolicyNone {
		t.Errorf("expected PolicyNone, got %q", policy)
	}
	if reason != "pass" {
		t.Errorf("expected reason 'pass', got %q", reason)
	}
}

func TestEvaluateBothAligned(t *testing.T) {
	p := NewPolicy()

	policy, reason, err := p.Evaluate("example.com", "example.com", true, "example.com", true)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if policy != msgauthdmarc.PolicyNone {
		t.Errorf("expected PolicyNone, got %q", policy)
	}
	if reason != "pass" {
		t.Errorf("expected reason 'pass', got %q", reason)
	}
}

func TestEvaluateNoAlignment(t *testing.T) {
	p := NewPolicy()

	policy, reason, err := p.Evaluate("example.com", "attacker.com", true, "attacker.com", true)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if policy != msgauthdmarc.PolicyNone {
		t.Errorf("expected PolicyNone, got %q", policy)
	}
	if reason != "no-dmarc-record" {
		t.Errorf("expected reason 'no-dmarc-record', got %q", reason)
	}
}

func TestEvaluateNoAlignmentNoPass(t *testing.T) {
	p := NewPolicy()

	// Neither SPF nor DKIM passes, and domains differ.
	policy, reason, err := p.Evaluate("example.com", "other.com", false, "other.com", false)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if policy != msgauthdmarc.PolicyNone {
		t.Errorf("expected PolicyNone, got %q", policy)
	}
	if reason != "no-dmarc-record" {
		t.Errorf("expected reason 'no-dmarc-record', got %q", reason)
	}
}

func TestEvaluateDomainMismatch(t *testing.T) {
	p := NewPolicy()

	// SPF passes but domain doesn't match; DKIM domain doesn't match either.
	policy, reason, err := p.Evaluate("example.com", "spf.other.com", true, "dkim.other.com", true)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	if policy != msgauthdmarc.PolicyNone {
		t.Errorf("expected PolicyNone, got %q", policy)
	}
	if reason != "no-dmarc-record" {
		t.Errorf("expected reason 'no-dmarc-record', got %q", reason)
	}
}

func TestNewPolicy(t *testing.T) {
	p := NewPolicy()
	if p == nil {
		t.Fatal("NewPolicy returned nil")
	}
}

func TestLookupAndEvaluateKnownDomainAligned(t *testing.T) {
	// gmail.com has a published DMARC policy. With alignment passing, should
	// return PolicyNone (no action needed).
	policy, err := LookupAndEvaluate("gmail.com", "gmail.com", true, "gmail.com", true)
	if err != nil {
		t.Fatalf("LookupAndEvaluate: %v", err)
	}
	if policy != msgauthdmarc.PolicyNone {
		t.Errorf("expected PolicyNone for aligned check on gmail.com, got %q", policy)
	}
}

func TestLookupAndEvaluateNoRecord(t *testing.T) {
	// A subdomain that won't have a DMARC record but whose parent exists.
	policy, err := LookupAndEvaluate("nonexistent-subdomain-that-does-not-exist.example.com",
		"attacker.com", true, "attacker.com", true)
	if err != nil {
		t.Fatalf("LookupAndEvaluate: %v", err)
	}
	// No DMARC record means PolicyNone with no error.
	if policy != msgauthdmarc.PolicyNone {
		t.Errorf("expected PolicyNone for domain without DMARC, got %q", policy)
	}
}

func TestLookupAndEvaluateAlignmentFailReject(t *testing.T) {
	// paypal.com has p=reject DMARC policy. When alignment fails, the policy
	// should be applied.
	policy, err := LookupAndEvaluate("paypal.com", "attacker.com", true, "attacker.com", true)
	if err != nil {
		t.Fatalf("LookupAndEvaluate: %v", err)
	}
	if policy != msgauthdmarc.PolicyReject {
		t.Errorf("expected PolicyReject for paypal.com with failed alignment, got %q", policy)
	}
}

func TestLookupAndEvaluateAlignmentFailQuarantine(t *testing.T) {
	// github.com has p=quarantine DMARC policy. When alignment fails, the policy
	// should be applied.
	policy, err := LookupAndEvaluate("github.com", "attacker.com", true, "attacker.com", true)
	if err != nil {
		t.Fatalf("LookupAndEvaluate: %v", err)
	}
	if policy != msgauthdmarc.PolicyQuarantine {
		t.Errorf("expected PolicyQuarantine for github.com with failed alignment, got %q", policy)
	}
}

// ---------------------------------------------------------------------------
// isAligned alignment helper tests
// ---------------------------------------------------------------------------

func TestIsAlignedExactMatch(t *testing.T) {
	// Exact match should align regardless of mode.
	if !isAligned("example.com", "example.com", msgauthdmarc.AlignmentRelaxed) {
		t.Error("expected relaxed exact match to align")
	}
	if !isAligned("example.com", "example.com", msgauthdmarc.AlignmentStrict) {
		t.Error("expected strict exact match to align")
	}
}

func TestIsAlignedSubdomainRelaxed(t *testing.T) {
	// Subdomain should match under relaxed mode.
	if !isAligned("sub.example.com", "example.com", msgauthdmarc.AlignmentRelaxed) {
		t.Error("expected subdomain to align under relaxed")
	}
	if !isAligned("deep.sub.example.com", "example.com", msgauthdmarc.AlignmentRelaxed) {
		t.Error("expected deep subdomain to align under relaxed")
	}
}

func TestIsAlignedSubdomainStrict(t *testing.T) {
	// Subdomain should NOT match under strict mode.
	if isAligned("sub.example.com", "example.com", msgauthdmarc.AlignmentStrict) {
		t.Error("expected subdomain to NOT align under strict")
	}
}

func TestIsAlignedDifferentDomain(t *testing.T) {
	// Different domain should not align.
	if isAligned("attacker.com", "example.com", msgauthdmarc.AlignmentRelaxed) {
		t.Error("expected different domain to not align under relaxed")
	}
	if isAligned("attacker.com", "example.com", msgauthdmarc.AlignmentStrict) {
		t.Error("expected different domain to not align under strict")
	}
}

func TestIsAlignedUnrelatedSubdomain(t *testing.T) {
	// Subdomain of a different domain should not align.
	if isAligned("sub.attacker.com", "example.com", msgauthdmarc.AlignmentRelaxed) {
		t.Error("expected subdomain of different domain to not align")
	}
}

func TestIsAlignedSameSuffixDifferentDomain(t *testing.T) {
	// Domain ending with claimedDomain as suffix (but not subdomain) should not align.
	if isAligned("notexample.com", "example.com", msgauthdmarc.AlignmentRelaxed) {
		t.Error("expected domain with similar suffix to not align")
	}
}

func TestIsAlignedEmptyDomain(t *testing.T) {
	// Empty domain should not align.
	if isAligned("", "example.com", msgauthdmarc.AlignmentRelaxed) {
		t.Error("expected empty domain to not align")
	}
}
