package storage

import (
	"context"

	"github.com/ghostshinobi/waf-killer/threat-intel/internal/aggregator"
	"github.com/redis/go-redis/v9"
)

type Storage struct {
	Redis    *RedisStorage
	Postgres *PostgresStorage
}

func NewStorage(redisClient *redis.Client, pgDSN string) *Storage {
	return &Storage{
		Redis:    &RedisStorage{client: redisClient},
		Postgres: NewPostgresStorage(pgDSN),
	}
}

func (s *Storage) StoreIndicators(ctx context.Context, indicators []aggregator.ThreatIndicator) error {
	// 1. Store in Redis (Hot Path)
	if err := s.Redis.StoreIndicators(ctx, indicators); err != nil {
		return err
	}
	
	// 2. Store in Postgres (Cold Path / Backup)
	// In a real system, this might be async or via a queue
	if err := s.Postgres.StoreIndicators(ctx, indicators); err != nil {
		// Log error but don't fail operation if Redis succeeded?
		// For now, return error
		return err
	}
	
	return nil
}

func (s *Storage) GetIPReputation(ctx context.Context, ip string) (*IPReputation, error) {
    // Read from Redis
	return s.Redis.GetIPReputation(ctx, ip)
}

type IPReputation struct {
	IP          string
	IsMalicious bool
	Confidence  float32
	Severity    aggregator.Severity
	Categories  []string
	Source      string
	LastSeen    int64
}
