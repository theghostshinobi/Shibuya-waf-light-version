package aggregator

import (
	"time"
)

type ThreatFeed interface {
	Name() string
	Fetch() ([]ThreatIndicator, error)
	UpdateInterval() time.Duration
}

type ThreatIndicator struct {
	Type       IndicatorType
	Value      string // "1.2.3.4"
	Confidence float32
	Severity   Severity
	Category   []string
	FirstSeen  time.Time
	LastSeen   time.Time
	Source     string
	TTL        time.Duration
	Metadata   map[string]string
}

type IndicatorType int

const (
	TypeIPv4 IndicatorType = iota
	TypeIPv6
	TypeDomain
	TypeURL
	TypeFileHash
)

type Severity int

const (
	SeverityUnknown  Severity = 0
	SeverityLow      Severity = 1
	SeverityMedium   Severity = 2
	SeverityHigh     Severity = 3
	SeverityCritical Severity = 4
)
