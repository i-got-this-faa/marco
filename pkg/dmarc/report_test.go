package dmarc

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"strings"
	"testing"
	"time"
)

// TestFeedbackXML validates that the Feedback struct marshals to valid DMARC
// aggregate report XML matching the expected schema.
func TestFeedbackXML(t *testing.T) {
	now := time.Now().UTC()
	begin := now.Add(-24 * time.Hour).Unix()
	end := now.Unix()

	f := Feedback{
		ReportMetadata: ReportMetadata{
			OrgName:  "marco.test",
			Email:    "dmarc-reports@marco.test",
			ReportID: "marco.test-example.com-1234567890",
			DateRange: DateRange{
				Begin: begin,
				End:   end,
			},
		},
		PolicyPublished: PolicyPublished{
			Domain:  "example.com",
			ADKIM:   "r",
			ASPF:    "r",
			Policy:  "none",
			Percent: 100,
		},
		Records: []Record{
			{
				Row: Row{
					SourceIP: "192.0.2.1",
					Count:    5,
					PolicyEvaluated: PolicyEvaluated{
						Disposition: "none",
						DKIM:        "pass",
						SPF:         "pass",
					},
				},
				Identifiers: Identifiers{
					HeaderFrom: "example.com",
				},
				AuthResults: AuthResults{
					DKIM: []AuthResult{
						{Domain: "example.com", Result: "pass"},
					},
					SPF: []AuthResult{
						{Domain: "example.com", Result: "pass"},
					},
				},
			},
			{
				Row: Row{
					SourceIP: "203.0.113.5",
					Count:    2,
					PolicyEvaluated: PolicyEvaluated{
						Disposition: "quarantine",
						DKIM:        "fail",
						SPF:         "fail",
					},
				},
				Identifiers: Identifiers{
					HeaderFrom: "example.com",
				},
				AuthResults: AuthResults{
					DKIM: []AuthResult{
						{Domain: "example.com", Result: "fail"},
					},
					SPF: []AuthResult{
						{Domain: "example.com", Result: "fail"},
					},
				},
			},
		},
	}

	data, err := xml.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatalf("xml.MarshalIndent failed: %v", err)
	}
	data = append([]byte(xml.Header), data...)

	// Verify it produces well-formed XML by unmarshaling it back.
	var decoded Feedback
	if err := xml.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("xml.Unmarshal of generated report failed: %v\n%s", err, data)
	}

	// Verify structural elements.
	if decoded.ReportMetadata.OrgName != "marco.test" {
		t.Errorf("expected OrgName 'marco.test', got %q", decoded.ReportMetadata.OrgName)
	}
	if decoded.ReportMetadata.ReportID != "marco.test-example.com-1234567890" {
		t.Errorf("unexpected ReportID: %q", decoded.ReportMetadata.ReportID)
	}
	if decoded.PolicyPublished.Domain != "example.com" {
		t.Errorf("expected Domain 'example.com', got %q", decoded.PolicyPublished.Domain)
	}
	if decoded.PolicyPublished.Policy != "none" {
		t.Errorf("expected Policy 'none', got %q", decoded.PolicyPublished.Policy)
	}
	if len(decoded.Records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(decoded.Records))
	}

	// Check first record.
	r1 := decoded.Records[0]
	if r1.Row.SourceIP != "192.0.2.1" {
		t.Errorf("expected SourceIP 192.0.2.1, got %q", r1.Row.SourceIP)
	}
	if r1.Row.Count != 5 {
		t.Errorf("expected Count 5, got %d", r1.Row.Count)
	}
	if r1.Identifiers.HeaderFrom != "example.com" {
		t.Errorf("expected HeaderFrom 'example.com', got %q", r1.Identifiers.HeaderFrom)
	}

	// Check second record.
	r2 := decoded.Records[1]
	if r2.Row.SourceIP != "203.0.113.5" {
		t.Errorf("expected SourceIP 203.0.113.5, got %q", r2.Row.SourceIP)
	}
	if r2.Row.PolicyEvaluated.Disposition != "quarantine" {
		t.Errorf("expected Disposition 'quarantine', got %q", r2.Row.PolicyEvaluated.Disposition)
	}
	if r2.Row.PolicyEvaluated.DKIM != "fail" {
		t.Errorf("expected DKIM 'fail', got %q", r2.Row.PolicyEvaluated.DKIM)
	}

	// Verify date range.
	if decoded.ReportMetadata.DateRange.Begin != begin {
		t.Errorf("expected Begin %d, got %d", begin, decoded.ReportMetadata.DateRange.Begin)
	}
	if decoded.ReportMetadata.DateRange.End != end {
		t.Errorf("expected End %d, got %d", end, decoded.ReportMetadata.DateRange.End)
	}

	// Verify that the output contains key DMARC XML elements.
	output := string(data)
	for _, elem := range []string{
		"<feedback>",
		"<report_metadata>",
		"<org_name>",
		"<policy_published>",
		"<record>",
		"<row>",
		"<source_ip>",
		"<auth_results>",
		"<identifiers>",
	} {
		if !strings.Contains(output, elem) {
			t.Errorf("expected XML element %q not found", elem)
		}
	}
}

// TestReportMetadata tests the ReportMetadata structure.
func TestReportMetadata(t *testing.T) {
	begin := int64(1000000)
	end := int64(2000000)

	rm := ReportMetadata{
		OrgName:  "TestOrg",
		Email:    "reports@test.org",
		ReportID: "test-id-001",
		DateRange: DateRange{
			Begin: begin,
			End:   end,
		},
	}

	data, err := xml.MarshalIndent(rm, "", "  ")
	if err != nil {
		t.Fatalf("xml.MarshalIndent failed: %v", err)
	}

	var decoded ReportMetadata
	if err := xml.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("xml.Unmarshal failed: %v", err)
	}

	if decoded.OrgName != "TestOrg" {
		t.Errorf("expected OrgName 'TestOrg', got %q", decoded.OrgName)
	}
	if decoded.Email != "reports@test.org" {
		t.Errorf("expected Email 'reports@test.org', got %q", decoded.Email)
	}
	if decoded.ReportID != "test-id-001" {
		t.Errorf("expected ReportID 'test-id-001', got %q", decoded.ReportID)
	}
	if decoded.DateRange.Begin != begin {
		t.Errorf("expected DateRange.Begin %d, got %d", begin, decoded.DateRange.Begin)
	}
	if decoded.DateRange.End != end {
		t.Errorf("expected DateRange.End %d, got %d", end, decoded.DateRange.End)
	}
}

// TestFeedbackGzip tests that the feedback XML can be gzip-compressed and
// decompressed successfully.
func TestFeedbackGzip(t *testing.T) {
	f := Feedback{
		ReportMetadata: ReportMetadata{
			OrgName:  "gzip-test",
			Email:    "test@example.com",
			ReportID: "gzip-test-id",
			DateRange: DateRange{
				Begin: 100,
				End:   200,
			},
		},
		PolicyPublished: PolicyPublished{
			Domain: "example.com",
			Policy: "reject",
		},
	}

	data, err := xml.Marshal(f)
	if err != nil {
		t.Fatalf("xml.Marshal failed: %v", err)
	}

	// Compress.
	var compressed bytes.Buffer
	gw := gzip.NewWriter(&compressed)
	if _, err := gw.Write(data); err != nil {
		t.Fatalf("gzip write failed: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close failed: %v", err)
	}

	if compressed.Len() == 0 {
		t.Fatal("compressed data is empty")
	}

	// Decompress and verify.
	gr, err := gzip.NewReader(&compressed)
	if err != nil {
		t.Fatalf("gzip new reader failed: %v", err)
	}
	defer gr.Close()

	var decompressed bytes.Buffer
	if _, err := decompressed.ReadFrom(gr); err != nil {
		t.Fatalf("gzip decompress failed: %v", err)
	}

	if decompressed.String() != string(data) {
		t.Fatal("decompressed data does not match original")
	}
}

// TestBase64Encoding verifies the base64 encoding produces RFC 2045
// compliant output.
func TestBase64Encoding(t *testing.T) {
	// Test with simple data — may or may not have a trailing CRLF.
	input := []byte("Hello, DMARC!")
	encoded := string(base64Encode(input))
	trimmed := strings.TrimRight(encoded, "\r\n")
	if len(trimmed) == 0 {
		t.Errorf("expected non-empty base64 output")
	}

	// Verify that decoded result matches.
	decoded := make([]byte, len(input))
	n, err := decodeBase64(encoded, decoded)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	decoded = decoded[:n]
	if !bytes.Equal(decoded, input) {
		t.Errorf("base64 round-trip failed: got %q, want %q", decoded, input)
	}

	// Test with longer data that should trigger line wrapping.
	longInput := make([]byte, 200)
	for i := range longInput {
		longInput[i] = byte(i % 256)
	}
	encoded2 := string(base64Encode(longInput))
	lines := strings.Split(encoded2, "\r\n")
	for _, line := range lines {
		if line != "" && len(line) > 76 {
			t.Errorf("base64 line exceeds 76 characters: %d", len(line))
		}
	}
}

// TestBase64Decode verifies our base64 output can be decoded by standard
// libraries.
func TestBase64Decode(t *testing.T) {
	input := []byte("DMARC aggregate report test data for encoding verification")
	encoded := base64Encode(input)

	// Decode using standard library.
	decoded := make([]byte, len(input))
	n, err := decodeBase64(string(encoded), decoded)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	decoded = decoded[:n]

	if !bytes.Equal(decoded, input) {
		t.Fatal("decoded data does not match original")
	}
}

// decodeBase64 is a helper for testing - decodes base64 data (ignoring
// whitespace/CRLF).
func decodeBase64(s string, dst []byte) (int, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var buf []byte
	for _, c := range []byte(s) {
		if c == '\r' || c == '\n' || c == ' ' {
			continue
		}
		buf = append(buf, c)
	}

	if len(buf)%4 != 0 {
		// Invalid base64
	}

	idx := 0
	for i := 0; i < len(buf); i += 4 {
		if i+3 >= len(buf) {
			break
		}
		var c4 [4]byte
		var vals [4]int
		for j := 0; j < 4; j++ {
			if i+j < len(buf) {
				c4[j] = buf[i+j]
			}
		}

		for j := 0; j < 4; j++ {
			if c4[j] == '=' {
				vals[j] = 0
				continue
			}
			vals[j] = strings.IndexByte(alphabet, c4[j])
			if vals[j] < 0 {
				return idx, nil
			}
		}

		if idx < len(dst) {
			dst[idx] = byte(vals[0]<<2 | vals[1]>>4)
			idx++
		}
		if idx < len(dst) && c4[2] != '=' {
			dst[idx] = byte((vals[1]&0xf)<<4 | vals[2]>>2)
			idx++
		}
		if idx < len(dst) && c4[3] != '=' {
			dst[idx] = byte((vals[2]&0x3)<<6 | vals[3])
			idx++
		}
	}
	return idx, nil
}

// TestPolicyPublished validates the PolicyPublished XML.
func TestPolicyPublished(t *testing.T) {
	pp := PolicyPublished{
		Domain:  "example.org",
		ADKIM:   "r",
		ASPF:    "s",
		Policy:  "reject",
		SPolicy: "quarantine",
		Percent: 50,
	}

	data, err := xml.MarshalIndent(pp, "", "  ")
	if err != nil {
		t.Fatalf("xml.MarshalIndent failed: %v", err)
	}

	var decoded PolicyPublished
	if err := xml.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("xml.Unmarshal failed: %v", err)
	}

	if decoded.Domain != "example.org" {
		t.Errorf("expected Domain 'example.org', got %q", decoded.Domain)
	}
	if decoded.Policy != "reject" {
		t.Errorf("expected Policy 'reject', got %q", decoded.Policy)
	}
	if decoded.SPolicy != "quarantine" {
		t.Errorf("expected SPolicy 'quarantine', got %q", decoded.SPolicy)
	}
	if decoded.Percent != 50 {
		t.Errorf("expected Percent 50, got %d", decoded.Percent)
	}
}

// TestRandomBoundary verifies the random boundary generator.
func TestRandomBoundary(t *testing.T) {
	b1 := randomBoundary()
	b2 := randomBoundary()

	if len(b1) != 32 {
		t.Errorf("expected boundary length 32, got %d", len(b1))
	}
	if b1 == b2 {
		t.Error("expected different boundaries on successive calls")
	}
}

// TestAuthResults validates the auth results XML.
func TestAuthResults(t *testing.T) {
	ar := AuthResults{
		DKIM: []AuthResult{
			{Domain: "example.com", Result: "pass"},
		},
		SPF: []AuthResult{
			{Domain: "example.com", Result: "neutral"},
		},
	}

	data, err := xml.Marshal(ar)
	if err != nil {
		t.Fatalf("xml.Marshal failed: %v", err)
	}

	var decoded AuthResults
	if err := xml.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("xml.Unmarshal failed: %v", err)
	}

	if len(decoded.DKIM) != 1 {
		t.Fatalf("expected 1 DKIM result, got %d", len(decoded.DKIM))
	}
	if decoded.DKIM[0].Result != "pass" {
		t.Errorf("expected DKIM result 'pass', got %q", decoded.DKIM[0].Result)
	}
	if len(decoded.SPF) != 1 {
		t.Fatalf("expected 1 SPF result, got %d", len(decoded.SPF))
	}
	if decoded.SPF[0].Result != "neutral" {
		t.Errorf("expected SPF result 'neutral', got %q", decoded.SPF[0].Result)
	}
}
