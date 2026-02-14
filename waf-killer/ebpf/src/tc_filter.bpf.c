// ebpf/src/tc_filter.bpf.c
// Placeholder for TC (Traffic Control) filter
// This can be used for egress filtering or more complex ingress logic later

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

SEC("classifier")
int tc_firewall(struct __sk_buff *skb) { return BPF_OK; }

char _license[] SEC("license") = "GPL";
