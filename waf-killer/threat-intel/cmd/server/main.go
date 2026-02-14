package main

import (
	"context"
	"log"
	"net"
	"os"
	"time"

	"github.com/ghostshinobi/waf-killer/threat-intel/internal/aggregator"
	"github.com/ghostshinobi/waf-killer/threat-intel/internal/api"
	"github.com/ghostshinobi/waf-killer/threat-intel/internal/storage"
	pb "github.com/ghostshinobi/waf-killer/threat-intel/proto"

	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
)

func main() {
	// 1. Load Config (Quick hack: hardcoded/env for now matching the yaml structure conceptually)
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}

	// 2. Init Storage
	redisClient := redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})
    _ = redisClient // suppress unused if we don't use it directly here
    
	store := storage.NewStorage(redisClient, "") // PG disabled for now

	// 3. Init Aggregators
	feeds := []aggregator.ThreatFeed{
        &aggregator.OTXFeed{APIKey: os.Getenv("OTX_API_KEY")},
        &aggregator.AbuseIPDBFeed{APIKey: os.Getenv("ABUSEIPDB_API_KEY")},
        &aggregator.TorFeed{},
        &aggregator.SpamhausFeed{},
	}

	// 4. Start Aggregation Loops
	for _, feed := range feeds {
		go runAggregationLoop(feed, store)
	}

	// 5. Start gRPC Server
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterThreatIntelServer(s, api.NewServer(store))
    
    log.Println("Threat Intel Service listening on :50051")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func runAggregationLoop(feed aggregator.ThreatFeed, store *storage.Storage) {
	ticker := time.NewTicker(feed.UpdateInterval())
	defer ticker.Stop()

    // Run once immediately
    log.Printf("[%s] Fetching indicators...", feed.Name())
    processFeed(feed, store)

	for range ticker.C {
		log.Printf("[%s] Fetching indicators...", feed.Name())
        processFeed(feed, store)
	}
}

func processFeed(feed aggregator.ThreatFeed, store *storage.Storage) {
    indicators, err := feed.Fetch()
    if err != nil {
        log.Printf("[%s] Error: %v", feed.Name(), err)
        return
    }

    log.Printf("[%s] Fetched %d indicators", feed.Name(), len(indicators))
    if len(indicators) > 0 {
        if err := store.StoreIndicators(context.Background(), indicators); err != nil {
            log.Printf("[%s] Storage error: %v", feed.Name(), err)
        }
    }
}
