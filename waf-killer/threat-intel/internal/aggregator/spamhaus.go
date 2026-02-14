package aggregator

import (
	"bufio"
	"net/http"
	"strings"
	"time"
)

type SpamhausFeed struct{}

func (f *SpamhausFeed) Name() string {
	return "Spamhaus DROP"
}

func (f *SpamhausFeed) Fetch() ([]ThreatIndicator, error) {
	url := "https://www.spamhaus.org/drop/drop.txt"

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	indicators := []ThreatIndicator{}

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, ";") {
			continue // Comment
		}

		parts := strings.Split(line, ";")
		if len(parts) < 1 {
			continue
		}

		cidr := strings.TrimSpace(parts[0])
		if cidr == "" {
			continue
		}

		indicators = append(indicators, ThreatIndicator{
			Type:       TypeIPv4, // It's a CIDR, needs handling in storage/matcher
			Value:      cidr,
			Confidence: 1.0,
			Severity:   SeverityCritical,
			Category:   []string{"spam", "malware", "botnet"},
			Source:     "Spamhaus DROP",
			TTL:        24 * time.Hour,
			FirstSeen:  time.Now(),
			LastSeen:   time.Now(),
		})
	}

	return indicators, nil
}

func (f *SpamhausFeed) UpdateInterval() time.Duration {
	return 6 * time.Hour
}
