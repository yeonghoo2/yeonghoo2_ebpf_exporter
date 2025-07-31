#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"

#define MAX_ENTRIES 8192

// TCP states
#define TCP_CLOSE_WAIT 8

#define AF_INET 2
#define AF_INET6 10

#define UPPER_PORT_BOUND 32768

struct close_wait_key_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 pid;
    u32 tgid;
};

struct close_wait_info_t {
    u64 timestamp;
    u32 state;
    u32 uid;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct close_wait_key_t);
    __type(value, struct close_wait_info_t);
} close_wait_sockets SEC(".maps");

static int extract_ports(const struct sock *sk, u16 *sport, u16 *dport)
{
    *sport = sk->__sk_common.skc_num;
    *dport = __builtin_bswap16(sk->__sk_common.skc_dport);

    if (*sport > UPPER_PORT_BOUND && *dport > UPPER_PORT_BOUND) {
        return 0;
    }

    return 1;
}

static int trace_ipv4_close_wait(const struct sock *sk, u32 state)
{
    u16 sport, dport;
    if (!extract_ports(sk, &sport, &dport)) {
        return 0;
    }

    struct close_wait_key_t key = {};
    struct close_wait_info_t info = {};

    key.saddr = sk->__sk_common.skc_rcv_saddr;
    key.daddr = sk->__sk_common.skc_daddr;
    key.sport = sport;
    key.dport = dport;
    key.pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    key.tgid = bpf_get_current_pid_tgid() >> 32;

    info.timestamp = bpf_ktime_get_ns();
    info.state = state;
    info.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    bpf_map_update_elem(&close_wait_sockets, &key, &info, BPF_ANY);

    return 0;
}

static int trace_ipv6_close_wait(const struct sock *sk, u32 state)
{
    u16 sport, dport;
    if (!extract_ports(sk, &sport, &dport)) {
        return 0;
    }

    struct close_wait_key_t key = {};
    struct close_wait_info_t info = {};

    // For IPv6, we'll use the first 4 bytes of the address as key
    // This is a simplification - in a real implementation you might want to handle IPv6 differently
    bpf_probe_read_kernel(&key.saddr, sizeof(key.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[0]);
    bpf_probe_read_kernel(&key.daddr, sizeof(key.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[0]);
    key.sport = sport;
    key.dport = dport;
    key.pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    key.tgid = bpf_get_current_pid_tgid() >> 32;

    info.timestamp = bpf_ktime_get_ns();
    info.state = state;
    info.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    bpf_map_update_elem(&close_wait_sockets, &key, &info, BPF_ANY);

    return 0;
}

static int trace_close_wait(const struct sock *sk, u32 state)
{
    switch (sk->__sk_common.skc_family) {
    case AF_INET:
        return trace_ipv4_close_wait(sk, state);
    case AF_INET6:
        return trace_ipv6_close_wait(sk, state);
    }

    return 0;
}

SEC("fentry/tcp_set_state")
int BPF_PROG(tcp_set_state, struct sock *sk, int state)
{
    // Only track when socket enters CLOSE_WAIT state
    if (state == TCP_CLOSE_WAIT) {
        return trace_close_wait(sk, state);
    }

    return 0;
}

// Also track when sockets are released to clean up the map
SEC("fentry/__sock_release")
int BPF_PROG(sock_release, struct socket *sock)
{
    if (!sock || !sock->sk) {
        return 0;
    }

    struct sock *sk = sock->sk;
    u16 sport, dport;
    
    if (!extract_ports(sk, &sport, &dport)) {
        return 0;
    }

    struct close_wait_key_t key = {};
    
    if (sk->__sk_common.skc_family == AF_INET) {
        key.saddr = sk->__sk_common.skc_rcv_saddr;
        key.daddr = sk->__sk_common.skc_daddr;
    } else if (sk->__sk_common.skc_family == AF_INET6) {
        bpf_probe_read_kernel(&key.saddr, sizeof(key.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[0]);
        bpf_probe_read_kernel(&key.daddr, sizeof(key.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[0]);
    }
    
    key.sport = sport;
    key.dport = dport;
    key.pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    key.tgid = bpf_get_current_pid_tgid() >> 32;

    bpf_map_delete_elem(&close_wait_sockets, &key);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";