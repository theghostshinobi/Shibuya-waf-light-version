package aggregator

import (
	"bufio"
	"net"
	"net/http"
	"time"
)

type TorFeed struct{}

func (f *TorFeed) Name() string {
	return "Tor Project"
}

func (f *TorFeed) Fetch() ([]ThreatIndicator, error) {
	url := "https://check.torproject.org/torbulkexitlist"

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	indicators := []ThreatIndicator{}

	for scanner.Scan() {
		ip := scanner.Text()
		if net.ParseIP(ip) != nil {
			indicators = append(indicators, ThreatIndicator{
				Type:       TypeIPv4,
				Value:      ip,
				Confidence: 1.0,
				Severity:   SeverityMedium, // Tor isn't inherently malicious
				Category:   []string{"tor-exit", "anonymizer"},
				Source:     "Tor Project",
				TTL:        6 * time.Hour,
				FirstSeen:  time.Now(),
				LastSeen:   time.Now(),
			})
		}
	}

	return indicators, nil
}

func (f *TorFeed) UpdateInterval() time.Duration {
	return 30 * time.Minute
}
