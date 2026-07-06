package spf

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Result describes the SPF verification outcome.
type Result struct {
	Code ResultCode
	Text string
}

// ResultCode enumerates SPF check results.
type ResultCode int

const (
	ResultNone     ResultCode = iota
	ResultPass
	ResultFail
	ResultSoftFail
	ResultNeutral
	ResultTempError
	ResultPermError
)

func (r ResultCode) String() string {
	switch r {
	case ResultPass:
		return "pass"
	case ResultFail:
		return "fail"
	case ResultSoftFail:
		return "softfail"
	case ResultNeutral:
		return "neutral"
	case ResultTempError:
		return "temperror"
	case ResultPermError:
		return "permerror"
	default:
		return "none"
	}
}

// Checker performs SPF checks against incoming mail using DNS.
type Checker struct {
	resolver *net.Resolver
}

// NewChecker creates a new SPF checker.
func NewChecker() *Checker {
	return &Checker{
		resolver: net.DefaultResolver,
	}
}

// Check performs an SPF check for the given IP, domain, and HELO name.
// The helo parameter is currently unused; the check is performed against
// the domain of the MAIL FROM address.
func (c *Checker) Check(ip net.IP, domain string, helo string) (Result, error) {
	spfRecord, err := c.lookupSPF(context.Background(), domain)
	if err != nil {
		return Result{Code: ResultTempError, Text: "dns lookup failed"}, nil
	}
	if spfRecord == "" {
		return Result{Code: ResultNone, Text: "no SPF record"}, nil
	}

	_ = helo
	return c.evaluate(context.Background(), ip, domain, spfRecord, 0)
}

// evaluate parses and evaluates an SPF record against the given IP.
// depth is the include nesting depth (max 10).
func (c *Checker) evaluate(ctx context.Context, ip net.IP, domain, spfRecord string, depth int) (Result, error) {
	if depth > 10 {
		return Result{Code: ResultPermError, Text: "max include depth exceeded"}, nil
	}

	terms := strings.Fields(spfRecord)
	for _, term := range terms {
		term = strings.TrimSpace(term)
		if term == "" || term == "v=spf1" {
			continue
		}

		// Check for redirect modifier (evaluated only if no mechanism matched).
		if strings.HasPrefix(term, "redirect=") {
			continue // handled after mechanism loop
		}

		// Check for exp modifier (informational, skip).
		if strings.HasPrefix(term, "exp=") {
			continue
		}

		qualifier := '+'
		mech := term
		if len(term) > 0 && (term[0] == '+' || term[0] == '-' || term[0] == '~' || term[0] == '?') {
			qualifier = rune(term[0])
			mech = term[1:]
		}

		var match bool
		var err error
		switch {
		case mech == "all":
			match = true
		case strings.HasPrefix(mech, "ip4:"):
			match, err = c.matchIP4(ip, mech[4:])
		case strings.HasPrefix(mech, "ip6:"):
			match, err = c.matchIP6(ip, mech[4:])
		case mech == "a":
			match, err = c.matchA(ctx, domain, ip)
		case strings.HasPrefix(mech, "a:"):
			match, err = c.matchA(ctx, mech[2:], ip)
		case strings.HasPrefix(mech, "a/") || strings.Contains(mech, ":"):
			// a:<domain>/<prefix-length> or a/<prefix-length>
			match, err = c.matchAWithCIDR(ctx, mech[2:], ip)
		case mech == "mx":
			match, err = c.matchMX(ctx, domain, ip, 32, 128)
		case strings.HasPrefix(mech, "mx:"):
			match, err = c.matchMX(ctx, mech[3:], ip, 32, 128)
		case strings.HasPrefix(mech, "mx/") || strings.Contains(mech, "mx:"):
			// mx:<domain>/<prefix-length> or mx/<prefix-length>
			match, err = c.matchMXWithCIDR(ctx, mech[3:], ip)
		case strings.HasPrefix(mech, "include:"):
			if depth >= 10 {
				return Result{Code: ResultPermError, Text: "max include depth exceeded"}, nil
			}
			match, err = c.evaluateInclude(ctx, ip, mech[8:], depth+1)
		default:
			// Unknown mechanism, ignore.
			continue
		}

		if err != nil {
			return Result{Code: ResultTempError, Text: fmt.Sprintf("dns error: %v", err)}, nil
		}

		if match {
			switch qualifier {
			case '+':
				return Result{Code: ResultPass, Text: "SPF pass"}, nil
			case '-':
				return Result{Code: ResultFail, Text: "SPF fail"}, nil
			case '~':
				return Result{Code: ResultSoftFail, Text: "SPF softfail"}, nil
			case '?':
				return Result{Code: ResultNeutral, Text: "SPF neutral"}, nil
			}
		}
	}

	// Check redirect= modifier (RFC 7208 section 6.1).
	for _, term := range terms {
		if strings.HasPrefix(term, "redirect=") {
			redirectDomain := term[9:]
			if redirectDomain == "" {
				return Result{Code: ResultPermError, Text: "empty redirect domain"}, nil
			}
			rec, err := c.lookupSPF(ctx, redirectDomain)
			if err != nil {
				return Result{Code: ResultTempError, Text: "redirect lookup failed"}, nil
			}
			if rec == "" {
				return Result{Code: ResultPermError, Text: "redirect target has no SPF"}, nil
			}
			return c.evaluate(ctx, ip, redirectDomain, rec, depth+1)
		}
	}

	// No mechanism matched: default result is Neutral.
	return Result{Code: ResultNeutral, Text: "no matching mechanism"}, nil
}

// matchIP4 checks if the IP matches an ip4 mechanism with optional CIDR.
func (c *Checker) matchIP4(ip net.IP, arg string) (bool, error) {
	if ip.To4() == nil {
		return false, nil
	}

	cidr := arg
	prefixLen := 32
	if i := strings.IndexByte(arg, '/'); i >= 0 {
		cidr = arg[:i]
		var err error
		prefixLen, err = strconv.Atoi(arg[i+1:])
		if err != nil || prefixLen < 0 || prefixLen > 32 {
			return false, nil
		}
	}

	netIP := net.ParseIP(cidr)
	if netIP == nil {
		return false, nil
	}
	net4 := netIP.To4()
	if net4 == nil {
		return false, nil
	}

	return cidrMatch(ip.To4(), net4, prefixLen), nil
}

// matchIP6 checks if the IP matches an ip6 mechanism with optional CIDR.
func (c *Checker) matchIP6(ip net.IP, arg string) (bool, error) {
	if ip.To16() == nil || ip.To4() != nil {
		return false, nil
	}

	cidr := arg
	prefixLen := 128
	if i := strings.IndexByte(arg, '/'); i >= 0 {
		cidr = arg[:i]
		var err error
		prefixLen, err = strconv.Atoi(arg[i+1:])
		if err != nil || prefixLen < 0 || prefixLen > 128 {
			return false, nil
		}
	}

	netIP := net.ParseIP(cidr)
	if netIP == nil {
		return false, nil
	}
	ip16 := netIP.To16()
	if ip16 == nil {
		return false, nil
	}

	return cidrMatch(ip.To16(), ip16, prefixLen), nil
}

// matchA checks if the IP matches any A or AAAA record for the given domain.
func (c *Checker) matchA(ctx context.Context, domain string, ip net.IP) (bool, error) {
	ips, err := c.resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return false, err
	}
	for _, addr := range ips {
		if addr.IP.Equal(ip) {
			return true, nil
		}
	}
	return false, nil
}

// matchAWithCIDR checks if the IP is in the CIDR range derived from the domain's A/AAAA records.
func (c *Checker) matchAWithCIDR(ctx context.Context, arg string, ip net.IP) (bool, error) {
	// Parse a:<domain>/<len> or a/<len>
	var domain string
	prefixLen := 32
	if ip.To4() == nil && ip.To16() != nil {
		prefixLen = 128
	}

	if i := strings.IndexByte(arg, '/'); i >= 0 {
		domain = arg[:i]
		n, err := strconv.Atoi(arg[i+1:])
		if err == nil {
			prefixLen = n
		}
	} else {
		domain = arg
	}

	ips, err := c.resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return false, err
	}
	for _, addr := range ips {
		if cidrMatch(ip, addr.IP, prefixLen) {
			return true, nil
		}
	}
	return false, nil
}

// matchMX checks if the IP matches any MX record's A/AAAA for the given domain.
func (c *Checker) matchMX(ctx context.Context, domain string, ip net.IP, v4bits, v6bits int) (bool, error) {
	mxes, err := c.resolver.LookupMX(ctx, domain)
	if err != nil {
		return false, err
	}
	if len(mxes) == 0 {
		return false, nil
	}
	for _, mx := range mxes {
		ips, err := c.resolver.LookupIPAddr(ctx, mx.Host)
		if err != nil {
			continue
		}
		for _, addr := range ips {
			if addr.IP.Equal(ip) {
				return true, nil
			}
		}
	}
	return false, nil
}

// matchMXWithCIDR handles mx with CIDR notation.
func (c *Checker) matchMXWithCIDR(ctx context.Context, arg string, ip net.IP) (bool, error) {
	var domain string
	prefixLen := 32
	if ip.To16() != nil && ip.To4() == nil {
		prefixLen = 128
	}

	if i := strings.IndexByte(arg, '/'); i >= 0 {
		domain = arg[:i]
		n, err := strconv.Atoi(arg[i+1:])
		if err == nil {
			prefixLen = n
		}
	} else {
		domain = arg
	}

	mxes, err := c.resolver.LookupMX(ctx, domain)
	if err != nil {
		return false, err
	}
	for _, mx := range mxes {
		ips, err := c.resolver.LookupIPAddr(ctx, mx.Host)
		if err != nil {
			continue
		}
		for _, addr := range ips {
			if cidrMatch(ip, addr.IP, prefixLen) {
				return true, nil
			}
		}
	}
	return false, nil
}

// evaluateInclude recursively evaluates a referenced domain's SPF record.
func (c *Checker) evaluateInclude(ctx context.Context, ip net.IP, domain string, depth int) (bool, error) {
	rec, err := c.lookupSPF(ctx, domain)
	if err != nil {
		return false, err
	}
	if rec == "" {
		return false, nil
	}

	result, err := c.evaluate(ctx, ip, domain, rec, depth)
	if err != nil {
		return false, err
	}
	// include matches if the referenced SPF result is Pass (RFC 7208 section 5.2).
	return result.Code == ResultPass, nil
}

func (c *Checker) lookupSPF(ctx context.Context, domain string) (string, error) {
	txts, err := c.resolver.LookupTXT(ctx, domain)
	if err != nil {
		return "", fmt.Errorf("spf: lookup TXT: %w", err)
	}
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=spf1") {
			return txt, nil
		}
	}
	return "", nil
}

// cidrMatch checks if an IP address falls within a CIDR prefix.
func cidrMatch(ip, network net.IP, bits int) bool {
	// Normalize to canonical form: 4-byte for IPv4, 16-byte for IPv6.
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	if n4 := network.To4(); n4 != nil {
		network = n4
	}

	if len(ip) != len(network) {
		return false
	}
	if bits <= 0 {
		return true
	}
	if bits >= len(ip)*8 {
		return ip.Equal(network)
	}

	fullBytes := bits / 8
	for i := 0; i < fullBytes; i++ {
		if ip[i] != network[i] {
			return false
		}
	}

	remaining := bits % 8
	if remaining > 0 && fullBytes < len(ip) {
		mask := byte(0xff << (8 - remaining))
		if ip[fullBytes]&mask != network[fullBytes]&mask {
			return false
		}
	}
	return true
}


// GetResolver returns the underlying resolver, useful for testing.
func (c *Checker) GetResolver() *net.Resolver {
	return c.resolver
}
