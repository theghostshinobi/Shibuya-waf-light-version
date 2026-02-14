package aggregator

import (
	"encoding/json"
	"net/http"
	"time"
)

type OTXFeed struct {
	APIKey string
}

type OTXPulse struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Created    time.Time      `json:"created"`
	Modified   time.Time      `json:"modified"`
	Tags       []string       `json:"tags"`
	Indicators []OTXIndicator `json:"indicators"`
}

type OTXIndicator struct {
	Indicator string `json:"indicator"`
	Type      string `json:"type"`
}

func (f *OTXFeed) Name() string {
	return "AlienVault OTX"
}

func (f *OTXFeed) Fetch() ([]ThreatIndicator, error) {
	// For MVP: In a real implementation this would fetch subscribed pulses
	// Here we'll mock it or use a public feed if available without heavy auth for simpler testing if API Key is missing.
	// Assuming API Key is present for this implementation.

	indicators := []ThreatIndicator{}
	if f.APIKey == "" {
		return indicators, nil
	}

	// This is a simplified endpoint structure. Real OTX API is comprehensive.
	// We'll use a hypothetical simplified call or just return empty if no key to prevent runtime errors during dev without keys.
    // In production code you would call: https://otx.alienvault.com/api/v1/pulses/subscribed
    
    // START SAFEGUARD: Return empty if no functionality to avoid crashing on missing credits/auth
    return indicators, nil
    // END SAFEGUARD
}

func (f *OTXFeed) UpdateInterval() time.Duration {
	return 15 * time.Minute
}

func (f *OTXFeed) mapSeverity(tags []string) Severity {
    // Simple heuristic
    for _, tag := range tags {
        if tag == "critical" || tag == "apt" {
            return SeverityCritical
        }
    }
    return SeverityMedium
}
