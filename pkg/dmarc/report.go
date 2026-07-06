package dmarc

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/xml"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/emersion/go-msgauth/dmarc"
	"github.com/i-got-this-faa/marco/pkg/blobstore"
	"github.com/i-got-this-faa/marco/pkg/queue"
	"github.com/i-got-this-faa/marco/pkg/storage"
)

// ---------------------------------------------------------------------------
// DMARC Aggregate Report XML types (RFC 7489 Appendix A)
// ---------------------------------------------------------------------------

// Feedback is the root element of a DMARC aggregate report.
type Feedback struct {
	XMLName         xml.Name       `xml:"feedback"`
	Version         string         `xml:"version,omitempty"`
	ReportMetadata  ReportMetadata `xml:"report_metadata"`
	PolicyPublished PolicyPublished `xml:"policy_published"`
	Records         []Record       `xml:"record"`
}

// ReportMetadata describes the report itself.
type ReportMetadata struct {
	OrgName          string    `xml:"org_name"`
	Email            string    `xml:"email"`
	ExtraContactInfo string    `xml:"extra_contact_info,omitempty"`
	ReportID         string    `xml:"report_id"`
	DateRange        DateRange `xml:"date_range"`
}

// DateRange specifies the time range covered by the report.
type DateRange struct {
	Begin int64 `xml:"begin"`
	End   int64 `xml:"end"`
}

// PolicyPublished describes the DMARC policy as published in DNS.
type PolicyPublished struct {
	Domain  string `xml:"domain"`
	ADKIM   string `xml:"adkim,omitempty"`
	ASPF    string `xml:"aspf,omitempty"`
	Policy  string `xml:"p"`
	SPolicy string `xml:"sp,omitempty"`
	Percent int    `xml:"pct,omitempty"`
	// Fo      string `xml:"fo,omitempty"`
}

// Record describes the DMARC evaluation results for a set of messages from
// a single source IP sharing the same results.
type Record struct {
	Row         Row         `xml:"row"`
	Identifiers Identifiers `xml:"identifiers"`
	AuthResults AuthResults `xml:"auth_results"`
}

// Row contains the per-message aggregate data.
type Row struct {
	SourceIP       string          `xml:"source_ip"`
	Count          int             `xml:"count"`
	PolicyEvaluated PolicyEvaluated `xml:"policy_evaluated"`
}

// PolicyEvaluated describes the DMARC disposition applied.
type PolicyEvaluated struct {
	Disposition string `xml:"disposition"`
	DKIM        string `xml:"dkim"`
	SPF         string `xml:"spf"`
	PolicyOverride *PolicyOverride `xml:"policy_override,omitempty"`
}

// PolicyOverride describes the reason for overriding the DMARC disposition.
type PolicyOverride struct {
	Type    string `xml:"type"`
	Comment string `xml:"comment,omitempty"`
}

// Identifiers identifies the messages.
type Identifiers struct {
	HeaderFrom string `xml:"header_from"`
	// EnvelopeFrom string `xml:"envelope_from,omitempty"`
	// EnvelopeTo   string `xml:"envelope_to,omitempty"`
}

// AuthResults contains the authentication results.
type AuthResults struct {
	DKIM []AuthResult `xml:"dkim,omitempty"`
	SPF  []AuthResult `xml:"spf,omitempty"`
}

// AuthResult describes a single authentication result.
type AuthResult struct {
	Domain string `xml:"domain"`
	Result string `xml:"result"`
	// HumanResult string `xml:"human_result,omitempty"`
}

// ---------------------------------------------------------------------------
// ReportGenerator
// ---------------------------------------------------------------------------

// ReportGenerator periodically generates and sends DMARC aggregate reports.
type ReportGenerator struct {
	db           *sql.DB
	blob         blobstore.Store
	queue        *queue.Manager
	orgName      string
	reportEmail  string // contact email for the report
	interval     time.Duration
	log          *slog.Logger
	stopCh       chan struct{}
}

// NewReportGenerator creates a new DMARC report generator.
func NewReportGenerator(db *sql.DB, blob blobstore.Store, qm *queue.Manager, orgName, reportEmail string, interval time.Duration) *ReportGenerator {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	return &ReportGenerator{
		db:          db,
		blob:        blob,
		queue:       qm,
		orgName:     orgName,
		reportEmail: reportEmail,
		interval:    interval,
		log:         slog.With("service", "dmarc-report"),
		stopCh:      make(chan struct{}),
	}
}

// Start launches the report generation loop.
func (g *ReportGenerator) Start(ctx context.Context) error {
	g.log.Info("dmarc report generator starting", "interval", g.interval)

	// Run one check immediately on startup.
	if err := g.generateReports(ctx); err != nil {
		g.log.Error("initial dmarc report generation failed", "error", err)
	}

	go g.loop(ctx)
	return nil
}

// Stop signals the generator to shut down.
func (g *ReportGenerator) Stop() {
	close(g.stopCh)
}

func (g *ReportGenerator) loop(ctx context.Context) {
	ticker := time.NewTicker(g.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-g.stopCh:
			return
		case <-ticker.C:
			if err := g.generateReports(ctx); err != nil {
				g.log.Error("dmarc report generation failed", "error", err)
			}
		}
	}
}

// generateReports checks for pending DMARC results and generates reports.
func (g *ReportGenerator) generateReports(ctx context.Context) error {
	domains, err := storage.GetDMARCDomains(ctx, g.db)
	if err != nil {
		return fmt.Errorf("dmarc report: get domains: %w", err)
	}
	if len(domains) == 0 {
		return nil
	}

	g.log.Info("generating dmarc aggregate reports", "domains", domains)

	var reportedDomains []string

	for _, domain := range domains {
		if err := g.generateDomainReport(ctx, domain); err != nil {
			g.log.Error("failed to generate report for domain",
				"domain", domain, "error", err)
			continue
		}
		reportedDomains = append(reportedDomains, domain)
	}

	// Mark reported domains as sent.
	if len(reportedDomains) > 0 {
		if err := storage.MarkDMARCResultsSent(ctx, g.db, reportedDomains); err != nil {
			return fmt.Errorf("dmarc report: mark sent: %w", err)
		}
	}

	return nil
}

// generateDomainReport generates and sends a DMARC aggregate report for one
// domain.
func (g *ReportGenerator) generateDomainReport(ctx context.Context, domain string) error {
	// Look up the DMARC record to find RUA addresses.
	record, err := dmarc.Lookup(domain)
	if err != nil {
		if err == dmarc.ErrNoPolicy {
			g.log.Debug("no dmarc record for domain", "domain", domain)
			return nil
		}
		return fmt.Errorf("dmarc lookup %s: %w", domain, err)
	}

	if len(record.ReportURIAggregate) == 0 {
		g.log.Debug("no rua for domain", "domain", domain)
		return nil
	}

	// Get aggregated results.
	results, err := storage.GetUnsentDMARCResults(ctx, g.db)
	if err != nil {
		return fmt.Errorf("get results: %w", err)
	}

	// Filter results for this domain.
	var domainResults []*storage.AggregatedDMARCResult
	for _, r := range results {
		if r.FromDomain == domain {
			domainResults = append(domainResults, r)
		}
	}

	if len(domainResults) == 0 {
		return nil
	}

	// Build the feedback XML.
	now := time.Now().UTC()
	begin := now.Add(-g.interval).Unix()
	end := now.Unix()

	reportID := fmt.Sprintf("%s-%s-%d", g.orgName, domain, now.Unix())

	feedback := Feedback{
		ReportMetadata: ReportMetadata{
			OrgName:  g.orgName,
			Email:    g.reportEmail,
			ReportID: reportID,
			DateRange: DateRange{
				Begin: begin,
				End:   end,
			},
		},
		PolicyPublished: PolicyPublished{
			Domain:  domain,
			ADKIM:   string(record.DKIMAlignment),
			ASPF:    string(record.SPFAlignment),
			Policy:  string(record.Policy),
			Percent: 100,
		},
	}

	if record.SubdomainPolicy != "" {
		feedback.PolicyPublished.SPolicy = string(record.SubdomainPolicy)
	}

	// Build records from aggregated results.
	for _, r := range domainResults {
		spfEval := "fail"
		if r.SPFPass > 0 && r.SPFFail == 0 {
			spfEval = "pass"
		} else if r.SPFPass > 0 && r.SPFFail > 0 {
			spfEval = "pass" // some passed
		}

		dkimEval := "fail"
		if r.DKIMPass > 0 && r.DKIMFail == 0 {
			dkimEval = "pass"
		} else if r.DKIMPass > 0 && r.DKIMFail > 0 {
			dkimEval = "pass" // some passed
		}

		disposition := r.Disposition
		if disposition == "" {
			disposition = "none"
		}

		// Determine the overall SFP and DKIM result for auth_results.
		spfResult := "fail"
		if r.SPFPass > 0 {
			spfResult = "pass"
		}
		dkimResult := "fail"
		if r.DKIMPass > 0 {
			dkimResult = "pass"
		}

		feedback.Records = append(feedback.Records, Record{
			Row: Row{
				SourceIP: r.SourceIP,
				Count:    r.Count,
				PolicyEvaluated: PolicyEvaluated{
					Disposition: disposition,
					DKIM:        dkimEval,
					SPF:         spfEval,
				},
			},
			Identifiers: Identifiers{
				HeaderFrom: domain,
			},
			AuthResults: AuthResults{
				DKIM: []AuthResult{
					{Domain: domain, Result: dkimResult},
				},
				SPF: []AuthResult{
					{Domain: domain, Result: spfResult},
				},
			},
		})
	}

	// Marshal XML.
	xmlData, err := xml.MarshalIndent(feedback, "", "  ")
	if err != nil {
		return fmt.Errorf("xml marshal: %w", err)
	}
	xmlData = append([]byte(xml.Header), xmlData...)

	// Compress with gzip.
	var compressed bytes.Buffer
	gw := gzip.NewWriter(&compressed)
	if _, err := gw.Write(xmlData); err != nil {
		return fmt.Errorf("gzip write: %w", err)
	}
	if err := gw.Close(); err != nil {
		return fmt.Errorf("gzip close: %w", err)
	}

	// Send report to each RUA address.
	for _, ruaURI := range record.ReportURIAggregate {
		if err := g.sendReport(ctx, ruaURI, compressed.Bytes(), domain, reportID); err != nil {
			g.log.Error("failed to send report",
				"rua", ruaURI, "domain", domain, "error", err)
		}
	}

	return nil
}

// sendReport composes an email with the gzip-compressed XML report as an
// attachment and enqueues it for delivery.
func (g *ReportGenerator) sendReport(ctx context.Context, ruaURI string, compressedReport []byte, domain, reportID string) error {
	// Extract email address from mailto: URI.
	email := ruaURI
	if len(email) > 7 && email[:7] == "mailto:" {
		email = email[7:]
	}

	// Compose MIME email with the gzip report as attachment.
	fromAddr := fmt.Sprintf("dmarc-report@%s", domain)
	subject := fmt.Sprintf("Report Domain: %s; Report-ID: %s", domain, reportID)

	filename := fmt.Sprintf("%s!%s!%d.xml.gz", domain, g.orgName, time.Now().UTC().Unix())

	boundary := randomBoundary()

	reportContentID := fmt.Sprintf("<%s@%s>", reportID, domain)

	var emailBuf bytes.Buffer
	emailBuf.WriteString(fmt.Sprintf("From: %s\r\n", fromAddr))
	emailBuf.WriteString(fmt.Sprintf("To: %s\r\n", email))
	emailBuf.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	emailBuf.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z)))
	emailBuf.WriteString("MIME-Version: 1.0\r\n")
	emailBuf.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=%s\r\n", boundary))
	emailBuf.WriteString("\r\n")
	emailBuf.WriteString("This is a multi-part message in MIME format.\r\n")
	emailBuf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	emailBuf.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	emailBuf.WriteString("Content-Transfer-Encoding: 7bit\r\n")
	emailBuf.WriteString("\r\n")
	emailBuf.WriteString("This is an aggregate DMARC report generated by the Marco mail server.\r\n")
	emailBuf.WriteString(fmt.Sprintf("Report-ID: %s\r\n", reportID))
	emailBuf.WriteString(fmt.Sprintf("Domain: %s\r\n", domain))
	emailBuf.WriteString("\r\n")
	emailBuf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	emailBuf.WriteString(fmt.Sprintf("Content-Type: application/gzip; name=%s\r\n", filename))
	emailBuf.WriteString("Content-Transfer-Encoding: base64\r\n")
	emailBuf.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=%s\r\n", filename))
	emailBuf.WriteString(fmt.Sprintf("Content-Description: %s\r\n", reportContentID))
	emailBuf.WriteString("\r\n")

	// Encode as base64 inline.
	encoded := base64Encode(compressedReport)
	emailBuf.Write(encoded)
	emailBuf.WriteString("\r\n")
	emailBuf.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	// Store the email as a blob.
	reportBytes := emailBuf.Bytes()
	blobKey, _, err := g.blob.Put(ctx, bytes.NewReader(reportBytes), map[string]string{
		"report":    "dmarc",
		"domain":    domain,
		"report-id": reportID,
	})
	if err != nil {
		return fmt.Errorf("store report blob: %w", err)
	}

	// Use the queue to send the report email.
	// First, store the report in the OUTBOUND queue via storage.Enqueue.
	// We create a message entry and enqueue it.
	mbox, err := storage.GetMailbox(ctx, g.db, 0, "OUTBOUND")
	if err != nil {
		return fmt.Errorf("get outbound mailbox: %w", err)
	}

	msgID, _, err := storage.InsertMessage(ctx, g.db, mbox.ID, blobKey,
		int64(len(reportBytes)), fromAddr, email, subject, 0)
	if err != nil {
		return fmt.Errorf("insert report message: %w", err)
	}

	if err := g.queue.Enqueue(msgID, email); err != nil {
		return fmt.Errorf("enqueue report: %w", err)
	}

	g.log.Info("dmarc report queued",
		"domain", domain,
		"rua", email,
		"report-id", reportID,
		"size", len(compressedReport),
	)

	return nil
}

// randomBoundary generates a random MIME boundary string.
func randomBoundary() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 32)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			b[i] = 'x'
			continue
		}
		b[i] = charset[n.Int64()]
	}
	return string(b)
}

// base64Encode returns the base64-encoded content with line wrapping at 76
// characters, as required by RFC 2045.
func base64Encode(data []byte) []byte {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var buf bytes.Buffer
	lineLen := 0

	for i := 0; i < len(data); i += 3 {
		// Handle the last chunk.
		remaining := len(data) - i
		var b3 [3]byte
		copy(b3[:], data[i:])

		var c4 [4]byte
		c4[0] = alphabet[b3[0]>>2]
		c4[1] = alphabet[((b3[0]&0x03)<<4)|(b3[1]>>4)]
		c4[2] = alphabet[((b3[1]&0x0F)<<2)|(b3[2]>>6)]
		c4[3] = alphabet[b3[2]&0x3F]

		if remaining < 3 {
			c4[3] = '='
			if remaining < 2 {
				c4[2] = '='
			}
		}

		for _, c := range c4 {
			buf.WriteByte(c)
			lineLen++
			if lineLen >= 76 {
				buf.WriteString("\r\n")
				lineLen = 0
			}
		}
	}

	return buf.Bytes()
}
