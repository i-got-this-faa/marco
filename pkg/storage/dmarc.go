package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// DMARCResult represents a single DMARC evaluation result for a message.
type DMARCResult struct {
	ID          int64  `json:"id"`
	SourceIP    string `json:"source_ip"`
	FromDomain  string `json:"from_domain"`
	SPFResult   string `json:"spf_result"`
	DKIMResult  string `json:"dkim_result"`
	Disposition string `json:"disposition"`
	Timestamp   int64  `json:"timestamp"`
	ReportSent  bool   `json:"report_sent"`
}

// InsertDMARCResult stores a DMARC evaluation result.
func InsertDMARCResult(ctx context.Context, db *sql.DB, sourceIP, fromDomain, spfResult, dkimResult, disposition string) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO dmarc_results (source_ip, from_domain, spf_result, dkim_result, disposition, timestamp)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		sourceIP, fromDomain, spfResult, dkimResult, disposition, time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("storage: insert dmarc result: %w", err)
	}
	return nil
}

// GetUnsentDMARCResults returns DMARC results that have not yet been included
// in a report, grouped by domain and source IP.
type AggregatedDMARCResult struct {
	SourceIP    string
	FromDomain  string
	SPFPass     int
	SPFFail     int
	DKIMPass    int
	DKIMFail    int
	Disposition string
	Count       int
	Timestamp   int64
}

// GetUnsentDMARCResults returns aggregated DMARC results that haven't been
// reported yet, grouped by domain and source IP.
func GetUnsentDMARCResults(ctx context.Context, db *sql.DB) ([]*AggregatedDMARCResult, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT source_ip, from_domain, disposition,
		       SUM(CASE WHEN spf_result = 'pass' THEN 1 ELSE 0 END) as spf_pass,
		       SUM(CASE WHEN spf_result != 'pass' THEN 1 ELSE 0 END) as spf_fail,
		       SUM(CASE WHEN dkim_result = 'pass' THEN 1 ELSE 0 END) as dkim_pass,
		       SUM(CASE WHEN dkim_result != 'pass' THEN 1 ELSE 0 END) as dkim_fail,
		       COUNT(*) as count,
		       MAX(timestamp) as last_ts
		FROM dmarc_results
		WHERE report_sent = 0
		GROUP BY from_domain, source_ip, disposition
		ORDER BY from_domain, source_ip`)
	if err != nil {
		return nil, fmt.Errorf("storage: query unsent dmarc results: %w", err)
	}
	defer rows.Close()

	var results []*AggregatedDMARCResult
	for rows.Next() {
		r := &AggregatedDMARCResult{}
		if err := rows.Scan(&r.SourceIP, &r.FromDomain, &r.Disposition,
			&r.SPFPass, &r.SPFFail, &r.DKIMPass, &r.DKIMFail,
			&r.Count, &r.Timestamp); err != nil {
			return nil, fmt.Errorf("storage: scan dmarc result: %w", err)
		}
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: dmarc results rows: %w", err)
	}
	return results, nil
}

// MarkDMARCResultsSent marks all unsent DMARC results for the given domains
// as having been reported.
func MarkDMARCResultsSent(ctx context.Context, db *sql.DB, domains []string) error {
	if len(domains) == 0 {
		return nil
	}
	return withTx(ctx, db, func(tx *sql.Tx) error {
		for _, domain := range domains {
			_, err := tx.ExecContext(ctx,
				`UPDATE dmarc_results SET report_sent = 1 WHERE from_domain = ? AND report_sent = 0`,
				domain,
			)
			if err != nil {
				return fmt.Errorf("storage: mark dmarc results sent for %s: %w", domain, err)
			}
		}
		return nil
	})
}

// GetDMARCDomains returns the distinct from_domain values from unsent DMARC results.
func GetDMARCDomains(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT DISTINCT from_domain FROM dmarc_results WHERE report_sent = 0`)
	if err != nil {
		return nil, fmt.Errorf("storage: query dmarc domains: %w", err)
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, fmt.Errorf("storage: scan dmarc domain: %w", err)
		}
		domains = append(domains, domain)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: dmarc domains rows: %w", err)
	}
	return domains, nil
}
