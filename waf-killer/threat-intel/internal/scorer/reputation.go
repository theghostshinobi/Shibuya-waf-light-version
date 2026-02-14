package scorer

import (
	"github.com/ghostshinobi/waf-killer/threat-intel/internal/aggregator"
)

type ReputationScorer struct{}

func (s *ReputationScorer) CalculateScore(indicators []aggregator.ThreatIndicator) float32 {
	if len(indicators) == 0 {
		return 0.0
	}

	var totalScore float32 = 0.0
	var weights float32 = 0.0

	for _, ind := range indicators {
		sourceWeight := s.getSourceWeight(ind.Source)
		score := ind.Confidence * float32(ind.Severity) * sourceWeight

		totalScore += score
		weights += sourceWeight
	}

	if weights == 0 {
		return 0.0
	}

	normalized := totalScore / (weights * 4.0) // Max severity is 4

	if normalized > 1.0 {
		normalized = 1.0
	}

	return normalized
}

func (s *ReputationScorer) getSourceWeight(source string) float32 {
	weights := map[string]float32{
		"AbuseIPDB":      1.0,
		"AlienVault OTX": 0.8,
		"Spamhaus DROP":  1.0,
		"Tor Project":    0.5,
	}

	if w, ok := weights[source]; ok {
		return w
	}
	return 0.5
}
