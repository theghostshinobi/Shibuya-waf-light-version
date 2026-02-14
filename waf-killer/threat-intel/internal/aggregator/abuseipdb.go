package aggregator

import (
	"encoding/json"
	"net/http"
	"time"
)

type AbuseIPDBFeed struct {
	APIKey string
}

type AbuseIPDBResponse struct {
	Data []struct {
		IPAddress            string    `json:"ipAddress"`
		AbuseConfidenceScore int       `json:"abuseConfidenceScore"`
		LastReportedAt       time.Time `json:"lastReportedAt"`
	} `json:"data"`
}

func (f *AbuseIPDBFeed) Name() string {
	return "AbuseIPDB"
}

func (f *AbuseIPDBFeed) Fetch() ([]ThreatIndicator, error) {
	if f.APIKey == "" {
		return []ThreatIndicator{}, nil
	}

	url := "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Key", f.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result AbuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	indicators := []ThreatIndicator{}
	for _, ip := range result.Data {
		indicators = append(indicators, ThreatIndicator{
			Type:       TypeIPv4,
			Value:      ip.IPAddress,
			Confidence: float32(ip.AbuseConfidenceScore) / 100.0,
			Severity:   SeverityCritical,
			Category:   []string{"abuse", "spam", "scanner"},
			LastSeen:   ip.LastReportedAt,
			Source:     "AbuseIPDB",
			TTL:        48 * time.Hour,
		})
	}

	return indicators, nil
}

func (f *AbuseIPDBFeed) UpdateInterval() time.Duration {
	return 1 * time.Hour
}
