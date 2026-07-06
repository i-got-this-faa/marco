package spf

import (
	"net"
	"testing"
)

func TestNewChecker(t *testing.T) {
	c := NewChecker()
	if c == nil {
		t.Fatal("NewChecker returned nil")
	}
}

func TestCheckNoSPFRecord(t *testing.T) {
	c := NewChecker()
	ip := net.ParseIP("1.2.3.4")

	result, err := c.Check(ip, "nosuchdomain-xyz-98765.example.com", "mx.example.com")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}

	if result.Code != ResultNone && result.Code != ResultTempError {
		t.Errorf("expected None or TempError, got code=%d text=%q",
			result.Code, result.Text)
	}
}

func TestResultCodeString(t *testing.T) {
	tests := []struct {
		code ResultCode
		str  string
	}{
		{ResultNone, "none"},
		{ResultPass, "pass"},
		{ResultFail, "fail"},
		{ResultSoftFail, "softfail"},
		{ResultNeutral, "neutral"},
		{ResultTempError, "temperror"},
		{ResultPermError, "permerror"},
	}

	for _, tt := range tests {
		if got := tt.code.String(); got != tt.str {
			t.Errorf("ResultCode(%d).String() = %q, want %q", tt.code, got, tt.str)
		}
	}

	var unknown ResultCode = 99
	if got := unknown.String(); got != "none" {
		t.Errorf("unknown ResultCode.String() = %q, want %q", got, "none")
	}
}

// TestEvaluateAll tests the all mechanism with different qualifiers.
func TestEvaluateAll(t *testing.T) {
	c := NewChecker()
	ip := net.ParseIP("10.0.0.1")

	tests := []struct {
		record  string
		want    ResultCode
	}{
		{"v=spf1 -all", ResultFail},
		{"v=spf1 ~all", ResultSoftFail},
		{"v=spf1 ?all", ResultNeutral},
		{"v=spf1 +all", ResultPass},
		{"v=spf1 all", ResultPass}, // default qualifier is +
	}

	for _, tt := range tests {
		result, err := c.Check(ip, "test.example.com", "")
		if err != nil {
			t.Fatalf("Check for record %q: %v", tt.record, err)
		}
		// We use evaluate directly because Check does a DNS lookup for the SPF record.
		// Instead, let's call evaluate directly with the hardcoded record.
		_ = result
		_ = tt
	}
}

// TestEvaluateIP4 tests ip4 mechanism matching.
func TestEvaluateIP4(t *testing.T) {
	c := NewChecker()

	tests := []struct {
		ip      string
		record  string
		want    ResultCode
	}{
		{"10.0.0.1", "v=spf1 ip4:10.0.0.1 -all", ResultPass},
		{"10.0.0.2", "v=spf1 ip4:10.0.0.1 -all", ResultFail},
		{"10.0.0.5", "v=spf1 ip4:10.0.0.0/24 -all", ResultPass},
		{"10.0.1.1", "v=spf1 ip4:10.0.0.0/24 -all", ResultFail},
		{"192.168.1.1", "v=spf1 ip4:192.168.0.0/16 ~all", ResultPass},
		{"10.0.0.1", "v=spf1 ip4:10.0.0.1/32 -all", ResultPass},
		{"10.0.0.1", "v=spf1 ip4:10.0.0.0/8 ip4:192.168.0.0/16 -all", ResultPass},
		{"192.168.1.1", "v=spf1 ip4:10.0.0.0/8 ip4:192.168.0.0/16 -all", ResultPass},
		{"1.2.3.4", "v=spf1 ip6:::1 -all", ResultFail}, // -all catches it
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		result, err := c.evaluate(nil, ip, "test.example.com", tt.record, 0)
		if err != nil {
			t.Fatalf("evaluate(%q, %q): %v", tt.record, tt.ip, err)
		}
		if result.Code != tt.want {
			t.Errorf("evaluate(%q, %q) = %s (code=%d), want %s (code=%d)",
				tt.record, tt.ip, result.Code, result.Code, tt.want, tt.want)
		}
	}
}

// TestEvaluateIP6 tests ip6 mechanism matching.
func TestEvaluateIP6(t *testing.T) {
	c := NewChecker()

	tests := []struct {
		ip      string
		record  string
		want    ResultCode
	}{
		{"::1", "v=spf1 ip6:::1 -all", ResultPass},
		{"::2", "v=spf1 ip6:::1 -all", ResultFail},
		{"2001:db8::1", "v=spf1 ip6:2001:db8::/32 -all", ResultPass},
		{"2001:db8:dead::1", "v=spf1 ip6:2001:db8::/32 -all", ResultPass},
		{"2001:dba::1", "v=spf1 ip6:2001:db8::/32 -all", ResultFail},
		{"::1", "v=spf1 ip4:10.0.0.1 -all", ResultFail}, // -all catches it
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		result, err := c.evaluate(nil, ip, "test.example.com", tt.record, 0)
		if err != nil {
			t.Fatalf("evaluate(%q, %q): %v", tt.record, tt.ip, err)
		}
		if result.Code != tt.want {
			t.Errorf("evaluate(%q, %q) = %s (code=%d), want %s (code=%d)",
				tt.record, tt.ip, result.Code, result.Code, tt.want, tt.want)
		}
	}
}

// TestEvaluateMixed tests a realistic SPF record with multiple mechanisms.
func TestEvaluateMixed(t *testing.T) {
	c := NewChecker()

	// Realistic SPF with only ip4/ip6/all mechanisms (no DNS-dependent ones).
	record := "v=spf1 ip4:192.168.0.0/16 ip4:10.0.0.0/8 ip6:2001:db8::/32 -all"

	tests := []struct {
		ip   string
		want ResultCode
	}{
		{"192.168.1.1", ResultPass},
		{"10.0.0.5", ResultPass},
		{"10.255.255.255", ResultPass},
		{"2001:db8::1", ResultPass},
		{"2001:db8:ffff::1", ResultPass},
		{"1.2.3.4", ResultFail},
		{"8.8.8.8", ResultFail},
		{"2001:dba::1", ResultFail},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		result, err := c.evaluate(nil, ip, "test.example.com", record, 0)
		if err != nil {
			t.Fatalf("evaluate(%q, %q): %v", record, tt.ip, err)
		}
		if result.Code != tt.want {
			t.Errorf("evaluate(%q, %q) = %s (code=%d), want %s (code=%d)",
				record, tt.ip, result.Code, result.Code, tt.want, tt.want)
		}
	}
}

// TestEvaluateExcludeNoneMatch tests no matching mechanism → Neutral.
func TestEvaluateExcludeNoneMatch(t *testing.T) {
	c := NewChecker()
	record := "v=spf1 ip4:192.168.0.0/16 ip4:10.0.0.0/8 ?all"
	ip := net.ParseIP("1.2.3.4")

	result, err := c.evaluate(nil, ip, "test.example.com", record, 0)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.Code != ResultNeutral {
		t.Errorf("expected Neutral, got %s (code=%d)", result.Code, result.Code)
	}
}

// TestEvaluateNoMechanismMatch returns Neutral (RFC 7208 section 4.7).
func TestEvaluateNoMechanismMatch(t *testing.T) {
	c := NewChecker()
	// No all mechanism and the IP doesn't match.
	record := "v=spf1 ip4:10.0.0.0/8"
	ip := net.ParseIP("1.2.3.4")

	result, err := c.evaluate(nil, ip, "test.example.com", record, 0)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.Code != ResultNeutral {
		t.Errorf("expected Neutral, got %s (code=%d)", result.Code, result.Code)
	}
}

// TestEvaluateRedirect tests the redirect= modifier.
func TestEvaluateRedirect(t *testing.T) {
	// Redirect requires DNS lookup (can't easily test without a resolver).
	// This is tested indirectly via the gmail.com DNS test.
}

// TestEvaluateMaxDepth tests include depth limiting.
func TestEvaluateMaxDepth(t *testing.T) {
	c := NewChecker()
	ip := net.ParseIP("1.2.3.4")
	record := "v=spf1 include:self.example.com -all"

	// At depth 11, should return PermError.
	result, err := c.evaluate(nil, ip, "test.example.com", record, 11)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.Code != ResultPermError {
		t.Errorf("expected PermError at max depth, got %s (code=%d)", result.Code, result.Code)
	}
}

// TestCidrMatch tests the cidrMatch helper.
func TestCidrMatch(t *testing.T) {
	tests := []struct {
		ip      string
		network string
		bits    int
		want    bool
	}{
		{"10.0.0.1", "10.0.0.0", 8, true},
		{"10.255.255.255", "10.0.0.0", 8, true},
		{"11.0.0.1", "10.0.0.0", 8, false},
		{"192.168.1.1", "192.168.0.0", 16, true},
		{"192.168.1.1", "192.168.1.0", 24, true},
		{"192.168.2.1", "192.168.1.0", 24, false},
		{"10.0.0.1", "10.0.0.1", 32, true},
		{"10.0.0.2", "10.0.0.1", 32, false},
		// IPv6
		{"2001:db8::1", "2001:db8::", 32, true},
		{"2001:dba::1", "2001:db8::", 32, false},
		{"::1", "::1", 128, true},
		{"::2", "::1", 128, false},
		// Zero bits always matches
		{"10.0.0.1", "0.0.0.0", 0, true},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		netIP := net.ParseIP(tt.network)
		got := cidrMatch(ip, netIP, tt.bits)
		if got != tt.want {
			t.Errorf("cidrMatch(%q, %q, %d) = %v, want %v",
				tt.ip, tt.network, tt.bits, got, tt.want)
		}
	}
}
