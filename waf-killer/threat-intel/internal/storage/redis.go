package storage

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ghostshinobi/waf-killer/threat-intel/internal/aggregator"
	"github.com/redis/go-redis/v9"
)

type RedisStorage struct {
	client *redis.Client
}

func (s *RedisStorage) StoreIndicators(ctx context.Context, indicators []aggregator.ThreatIndicator) error {
	pipe := s.client.Pipeline()

	for _, ind := range indicators {
		if ind.Type == aggregator.TypeIPv4 {
			key := fmt.Sprintf("threat:ip:%s", ind.Value)

			data := map[string]interface{}{
				"confidence": ind.Confidence,
				"severity":   int(ind.Severity),
				"category":   strings.Join(ind.Category, ","),
				"source":     ind.Source,
				"last_seen":  ind.LastSeen.Unix(),
			}

			pipe.HMSet(ctx, key, data)
			pipe.Expire(ctx, key, ind.TTL)

			// Add to ranked set
			score := float64(ind.Confidence * float32(ind.Severity))
			pipe.ZAdd(ctx, "threat:ips:ranked", redis.Z{
				Score:  score,
				Member: ind.Value,
			})
		}
	}

	_, err := pipe.Exec(ctx)
	return err
}

func (s *RedisStorage) GetIPReputation(ctx context.Context, ip string) (*IPReputation, error) {
	key := fmt.Sprintf("threat:ip:%s", ip)

	data, err := s.client.HGetAll(ctx, key).Result()
	if err == redis.Nil || len(data) == 0 {
		return nil, nil // Not found
	}
	if err != nil {
		return nil, err
	}

	// Helper to parse safely
	parseFloat := func(s string) float32 {
		f, _ := strconv.ParseFloat(s, 32)
		return float32(f)
	}
	parseInt := func(s string) int {
		i, _ := strconv.Atoi(s)
		return i
	}
    parseInt64 := func(s string) int64 {
        i, _ := strconv.ParseInt(s, 10, 64)
        return i
    }

	return &IPReputation{
		IP:          ip,
		IsMalicious: true,
		Confidence:  parseFloat(data["confidence"]),
		Severity:    aggregator.Severity(parseInt(data["severity"])),
		Categories:  strings.Split(data["category"], ","),
		Source:      data["source"],
        LastSeen:    parseInt64(data["last_seen"]),
	}, nil
}

func (s *RedisStorage) SubscribeUpdates(ctx context.Context) *redis.PubSub {
    return s.client.Subscribe(ctx, "threat_updates")
}
