#include <linux/ip.h>
#include <linux/tcp.h>

struct tcp_session_key {
  __be32 saddr;
  __be32 daddr;
  __be16 sport;
  __be16 dport;
};

struct handshake_status {
  uint64_t begin_time;
  bool synack_sent;
} __attribute__((packed));

BPF_TABLE("lru_hash", struct tcp_session_key, struct handshake_status,
          pending_handshakes, 1024);

int monitor_ingress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
	
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    return TC_ACT_SHOT;
  }

  if (eth->h_proto != htons(ETH_P_IP)) {
    return TC_ACT_OK;
  }

  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end) {
    return TC_ACT_SHOT;
  }

  if (ip->protocol != IPPROTO_TCP) {
    return TC_ACT_OK;
  }

  struct tcphdr *tcp = (void *)ip + (ip->ihl << 2); 
  if ((void *)(tcp + 1) > data_end) {
    return TC_ACT_SHOT;
  }

  struct tcp_session_key session = {
    .saddr = ip->saddr,
    .daddr = ip->daddr,
    .sport = tcp->source,
    .dport = tcp->dest
  };

  if (tcp->syn && !tcp->ack) {
    struct handshake_status *handshake = pending_handshakes.lookup(&session);
    if (!handshake) {
      // New handshake
      struct handshake_status new_handshake = {
        .begin_time = bpf_ktime_get_ns(),  // Can be replaced with manual clock
                                           // if overhead is too much
        .synack_sent = false
      };

      pending_handshakes.update(&session, &new_handshake);
    }
  
  } else if (tcp->ack && !tcp->syn) {
    struct handshake_status *handshake = pending_handshakes.lookup(&session);
    if (handshake && handshake->synack_sent) {
      // Handshake completed
      pending_handshakes.delete(&session);
    }
  }

  return TC_ACT_OK;
}

int monitor_egress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
	
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    return TC_ACT_SHOT;
  }

  if (eth->h_proto != htons(ETH_P_IP)) {
    return TC_ACT_OK;
  }

  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end) {
    return TC_ACT_SHOT;
  }

  if (ip->protocol != IPPROTO_TCP) {
    return TC_ACT_OK;
  }

  struct tcphdr *tcp = (void *)ip + (ip->ihl << 2); 
  if ((void *)(tcp + 1) > data_end) {
    return TC_ACT_SHOT;
  }

  if (tcp->syn && tcp->ack) {
    // Session key is stored in ingress format, src and dst must be swapped for
    // egress packets
    struct tcp_session_key session = {
      .saddr = ip->daddr,
      .daddr = ip->saddr,
      .sport = tcp->dest,
      .dport = tcp->source
    };

    struct handshake_status *handshake = pending_handshakes.lookup(&session);
    if (handshake) {
      handshake->synack_sent = true;
    }
  }

  return TC_ACT_OK;
}