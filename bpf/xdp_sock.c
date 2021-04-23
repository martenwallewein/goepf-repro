// #include <linux/bpf.h>
// #include <bpf/bpf_helpers.h>
#include "bpf_helpers.h"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

BPF_MAP_DEF(rxcnt) = {
    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 256,
};
BPF_MAP_ADD(rxcnt);

static inline void count_tx(__u32 protocol)
{
	__u64 *rxcnt_count;
    rxcnt_count = bpf_map_lookup_elem(&rxcnt, &protocol);
    
    if (rxcnt_count)
        *rxcnt_count += 1;
}

SEC("xdp") int xdp_sock(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    size_t offset = sizeof(struct ether_header) +
                    sizeof(struct iphdr);
          
    if(data + offset > data_end) {
        return XDP_PASS; // too short
    }
    count_tx(0);
    const struct ether_header *eh = (const struct ether_header *)data;
    // FIXME: Without htons|bpf_htons it works as expected, with one of them we got
    // LoadElf() failed: loadPrograms() failed: Invalid BPF instruction (at 144): &{133 0 1 0 4294967295}
    if(eh->ether_type != htons(ETHERTYPE_IP)) {
       return XDP_PASS; // not IP
    }

    // FIXME: THis somehow depends on this instruction
    // If we have a map lookup after this htons instructions, the error occurs
    count_tx(1);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
