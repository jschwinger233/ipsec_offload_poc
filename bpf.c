#include <string.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

__attribute__((section("veth2nsim"), used))
int bpf_v2n(struct __sk_buff *skb) {
	return bpf_redirect(IFINDEX_NSIM, BPF_F_INGRESS);
}

__attribute__((section("nsim2veth"), used))
int bpf_n2v(struct __sk_buff *skb) {
	return bpf_redirect(IFINDEX_VETH, 0);
}

__attribute__((section("nsim_ingress"), used))
int bpf_packet_host(struct __sk_buff *skb) {
	bpf_skb_change_type(skb, PACKET_HOST);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
