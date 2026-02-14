package api

import (
	"context"
	"encoding/json"

	"github.com/ghostshinobi/waf-killer/threat-intel/internal/scorer"
	"github.com/ghostshinobi/waf-killer/threat-intel/internal/storage"
	pb "github.com/ghostshinobi/waf-killer/threat-intel/proto"
)

type ThreatIntelServer struct {
	pb.UnimplementedThreatIntelServer
	Storage *storage.Storage
	Scorer  *scorer.ReputationScorer
}

func NewServer(s *storage.Storage) *ThreatIntelServer {
	return &ThreatIntelServer{
		Storage: s,
		Scorer:  &scorer.ReputationScorer{},
	}
}

func (s *ThreatIntelServer) CheckIP(ctx context.Context, req *pb.CheckIPRequest) (*pb.CheckIPResponse, error) {
	rep, err := s.Storage.GetIPReputation(ctx, req.Ip)
	if err != nil {
		return nil, err
	}

	if rep == nil {
		return &pb.CheckIPResponse{
			Ip:          req.Ip,
			IsMalicious: false,
			Confidence:  0.0,
		}, nil
	}

	return &pb.CheckIPResponse{
		Ip:           req.Ip,
		IsMalicious:  true, // In this simplified model, presence = malicious/threat
		Confidence:   rep.Confidence,
		Severity:     int32(rep.Severity),
		Categories:   rep.Categories,
		Source:       rep.Source,
		LastSeenUnix: rep.LastSeen,
	}, nil
}

func (s *ThreatIntelServer) SubscribeUpdates(req *pb.SubscribeRequest, stream pb.ThreatIntel_SubscribeUpdatesServer) error {
	pubsub := s.Storage.Redis.SubscribeUpdates(stream.Context())
	defer pubsub.Close()

	ch := pubsub.Channel()

	for msg := range ch {
		var update pb.ThreatUpdate
		if err := json.Unmarshal([]byte(msg.Payload), &update); err != nil {
			continue // Skip malformed
		}

		if err := stream.Send(&update); err != nil {
			return err
		}
	}
	return nil
}

func (s *ThreatIntelServer) ReportIP(ctx context.Context, req *pb.ReportIPRequest) (*pb.ReportIPResponse, error) {
	// Logic to accept user reports and potentially add to a "community" feed
	// For now just log it
	return &pb.ReportIPResponse{
		Success: true,
		Message: "Report received",
	}, nil
}

func (s *ThreatIntelServer) CheckIPBatch(ctx context.Context, req *pb.CheckIPBatchRequest) (*pb.CheckIPBatchResponse, error) {
    results := make(map[string]*pb.CheckIPResponse)
    
    for _, ip := range req.Ips {
        resp, err := s.CheckIP(ctx, &pb.CheckIPRequest{Ip: ip})
        if err == nil {
            results[ip] = resp
        }
    }
    
    return &pb.CheckIPBatchResponse{Results: results}, nil
}
