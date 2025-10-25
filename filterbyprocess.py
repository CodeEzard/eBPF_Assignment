from bcc import BPF
import ctypes
import os
import socket
from time import sleep
import netifaces

TARGET_PROCESS = "myprocess"
TARGET_PORT = 4040

def get_default_interface():
    gateways = netifaces.gateways()
    default_iface = gateways.get('default', {}).get(netifaces.AF_INET)
    if default_iface:
        return default_iface[1]
    return "lo"

DEVICE = get_default_interface()
print(f"[INFO] Using network interface: {DEVICE}")

# convert port to network byte order (big-endian) constant for C
PORT_BE = socket.htons(TARGET_PORT)

bpf_program = f"""
#include <uapi/linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/if_ether.h>

struct val_t {{
    char name[16];
}};

BPF_HASH(pid_to_name, u32, struct val_t);

int filter_packet(struct __sk_buff *skb) {{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct val_t *v = pid_to_name.lookup(&pid);
    if (!v) {{
        return BPF_OK;
    }}

    unsigned char ip_hdr[20];
    if (bpf_skb_load_bytes(skb, 0, ip_hdr, sizeof(ip_hdr)) < 0) {{
        return BPF_OK;
    }}

    // check IPv4
    if ((ip_hdr[0] >> 4) != 4) {{
        return BPF_OK;
    }}

    // IHL in 32-bit words; header length in bytes:
    unsigned int ihl = (ip_hdr[0] & 0x0f) * 4;
    if (ihl < 20) {{
        return BPF_OK;
    }}

    // load first 4 bytes of TCP header (src port + dst port)
    unsigned char tcp_ports[4];
    if (bpf_skb_load_bytes(skb, ihl, tcp_ports, sizeof(tcp_ports)) < 0) {{
        return BPF_OK;
    }}

    unsigned short dport = ((unsigned short)tcp_ports[2] << 8) | tcp_ports[3];

    if (dport != {PORT_BE}) {{
        return BPF_DROP;
    }}

    return BPF_OK;
}}
"""

b = BPF(text=bpf_program)
fn = b.load_func("filter_packet", BPF.SOCKET_FILTER)
BPF.attach_raw_socket(fn, DEVICE)

pid_map = b.get_table("pid_to_name")

class Val(ctypes.Structure):
    _fields_ = [("name", ctypes.c_char * 16)]

def update_pid_map():
    existing_keys = set(int(k.value) for k in pid_map.keys())
    discovered = set()
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                name = f.read().strip()
        except Exception:
            continue
        if name == TARGET_PROCESS:
            discovered.add(int(pid))
            if int(pid) not in existing_keys:
                key = ctypes.c_uint(int(pid))
                val = Val()
                # ensure null-terminated / truncated to 15 chars
                bname = TARGET_PROCESS.encode()[:15]
                val.name = bname + b"\x00" * (16 - len(bname))
                pid_map[key] = val
    # optionally remove dead pids from map
    for k in list(pid_map.keys()):
        if int(k.value) not in discovered:
            del pid_map[k]

update_pid_map()
print(f"[INFO] Filtering traffic for process '{TARGET_PROCESS}' on port {TARGET_PORT}...")
print("[INFO] Press Ctrl+C to exit.")

try:
    while True:
        update_pid_map()
        sleep(2)
except KeyboardInterrupt:
    print("Detaching...")
