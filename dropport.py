#!/usr/bin/env python3
from bcc import BPF
import ctypes
import sys
import time
import socket

code = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/in.h>

BPF_ARRAY(ports, u16, 1);
BPF_ARRAY(drops, u64, 1);

int block_tcp(struct xdp_md *ctx) {
    void *d = (void *)(long)ctx->data;
    void *de = (void *)(long)ctx->data_end;

    struct ethhdr *eth = d;
    if ((void*)eth + sizeof(*eth) > de)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = d + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) > de)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    int iplen = ip->ihl * 4;
    struct tcphdr *tcp = (void*)ip + iplen;
    if ((void*)tcp + sizeof(*tcp) > de)
        return XDP_PASS;

    int k = 0;
    u16 *p = ports.lookup(&k);
    if (!p)
        return XDP_PASS;

    if (tcp->dest == bpf_htons(*p)) {
        u64 *c = drops.lookup(&k);
        if (c)
            (*c)++;
        return XDP_DROP;
    }

    return XDP_PASS;
}
"""

if len(sys.argv) < 2:
    print("Usage: sudo python3 drop_tcp_port.py <iface> [port]")
    sys.exit(1)

iface = sys.argv[1]
port = int(sys.argv[2]) if len(sys.argv) > 2 else 4040

b = BPF(text=code)
fn = b.load_func("block_tcp", BPF.XDP)
# Use generic (skb) mode by default for broader compatibility
b.attach_xdp(iface, fn, 2)

# Store port in host byte order; the eBPF program applies bpf_htons()
b["ports"][ctypes.c_int(0)] = ctypes.c_ushort(port)

print(f"Blocking TCP port {port} on {iface}")

try:
    dmap = b["drops"]
    while True:
        time.sleep(2)
        count = dmap[ctypes.c_int(0)].value
        print(f"Dropped: {count}")
except KeyboardInterrupt:
    pass
finally:
    b.remove_xdp(iface, 2)
