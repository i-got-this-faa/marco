package dmarc

import (
	"fmt"
	"strings"

	"github.com/emersion/go-msgauth/dmarc"
)

// Policy evaluates DMARC policy for incoming mail.
type Policy struct{}

// NewPolicy creates a new DMARC policy evaluator.
func NewPolicy() *Policy {
	return &Policy{}
}

// Evaluate checks DMARC alignment given SPF and DKIM results.
// It returns "pass" when either SPF or DKIM is aligned, otherwise a
// "no-dmarc-record" reason string.
func (p *Policy) Evaluate(claimedDomain string, spfDomain string, spfPass bool,
	dkimDomain string, dkimPass bool) (dmarc.Policy, string, error) {

	spfAligned := spfPass && spfDomain == claimedDomain
	dkimAligned := dkimPass && dkimDomain == claimedDomain

	if spfAligned || dkimAligned {
		return dmarc.PolicyNone, "pass", nil
	}

	return dmarc.PolicyNone, "no-dmarc-record", nil
}

// LookupAndEvaluate fetches the DMARC record for a domain and evaluates
// the policy against the given alignment results, respecting the record's
// alignment mode (relaxed vs strict).
func LookupAndEvaluate(claimedDomain string, spfDomain string, spfPass bool,
	dkimDomain string, dkimPass bool) (dmarc.Policy, error) {

	record, err := dmarc.Lookup(claimedDomain)
	if err != nil {
		if err == dmarc.ErrNoPolicy {
			return dmarc.PolicyNone, nil
		}
		return dmarc.PolicyNone, fmt.Errorf("dmarc: lookup: %w", err)
	}

	spfAligned := spfPass && isAligned(spfDomain, claimedDomain, record.SPFAlignment)
	dkimAligned := dkimPass && isAligned(dkimDomain, claimedDomain, record.DKIMAlignment)

	if !spfAligned && !dkimAligned {
		return record.Policy, nil
	}

	return dmarc.PolicyNone, nil
}

// isAligned checks whether the sender domain is aligned with the claimed
// domain according to the DMARC alignment mode.
//   - Relaxed: domain must equal claimedDomain or be a subdomain of it.
//   - Strict:  domain must equal claimedDomain exactly.
func isAligned(domain, claimedDomain string, alignment dmarc.AlignmentMode) bool {
	if !strings.Contains(domain, ".") {
		return false
	}
	if alignment == dmarc.AlignmentRelaxed {
		return domain == claimedDomain || strings.HasSuffix(domain, "."+claimedDomain)
	}
	return domain == claimedDomain
}
