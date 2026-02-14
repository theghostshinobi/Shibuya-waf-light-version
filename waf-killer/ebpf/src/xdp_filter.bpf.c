// ebpf/src/xdp_filter.bpf.c

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// BPF maps (shared between kernel and user-space)

// IP blocklist (10M entries, optimized for fast lookup)
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10000000); // 10M IPs
  __type(key, __u32);            // IP address (network byte order)
  __type(value, __u64);          // Timestamp when blocked
} ip_blocklist SEC(".maps");

// Per-IP rate limiting state
struct rate_limit_state {
  __u64 last_reset;   // Last time counter was reset
  __u32 packet_count; // Packets in current window
  __u32 limit;        // Max packets per window
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1000000); // 1M tracked IPs
  __type(key, __u32);
  __type(value, struct rate_limit_state);
} rate_limits SEC(".maps");

// Statistics
struct stats {
  __u64 total_packets;
  __u64 blocked_packets;
  __u64 rate_limited_packets;
  __u64 allowed_packets;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct stats);
} statistics SEC(".maps");

// Helper: Get current time in nanoseconds
static __always_inline __u64 get_time_ns(void) { return bpf_ktime_get_ns(); }

// Helper: Extract source IP from packet
static __always_inline __u32 get_src_ip(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // Parse Ethernet header
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return 0;

  // Only process IPv4
  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return 0;

  // Parse IP header
  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end)
    return 0;

  return ip->saddr;
}

// Helper: Check rate limit
static __always_inline int check_rate_limit(__u32 src_ip) {
  struct rate_limit_state *state = bpf_map_lookup_elem(&rate_limits, &src_ip);

  __u64 now = get_time_ns();
  __u64 window_ns = 1000000000; // 1 second window

  if (!state) {
    // First packet from this IP, allow and create state
    struct rate_limit_state new_state = {
        .last_reset = now,
        .packet_count = 1,
        .limit = 1000, // Default: 1000 req/s
    };
    bpf_map_update_elem(&rate_limits, &src_ip, &new_state, BPF_ANY);
    return 0; // Allow
  }

  // Reset counter if window expired
  if (now - state->last_reset > window_ns) {
    state->last_reset = now;
    state->packet_count = 1;
    return 0; // Allow
  }

  // Check if over limit
  if (state->packet_count >= state->limit) {
    return 1; // Drop (rate limited)
  }

  // Increment counter
  state->packet_count++;
  return 0; // Allow
}

// Main XDP program
SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
  // Update statistics
  __u32 key = 0;
  struct stats *stats = bpf_map_lookup_elem(&statistics, &key);
  if (stats) {
    stats->total_packets++;
  }

  // Extract source IP
  __u32 src_ip = get_src_ip(ctx);
  if (src_ip == 0) {
    return XDP_PASS; // Invalid packet or non-IPv4, let kernel handle
  }

  // Check IP blocklist (fastest check)
  if (bpf_map_lookup_elem(&ip_blocklist, &src_ip)) {
    if (stats) {
      stats->blocked_packets++;
    }
    return XDP_DROP; // Blocked IP, drop immediately
  }

  // Check rate limit
  if (check_rate_limit(src_ip)) {
    if (stats) {
      stats->rate_limited_packets++;
    }
    return XDP_DROP; // Rate limited, drop
  }

  // All checks passed, send to user-space WAF
  if (stats) {
    stats->allowed_packets++;
  }

  return XDP_PASS; // Pass to kernel network stack
}

char _license[] SEC("license") = "GPL";
