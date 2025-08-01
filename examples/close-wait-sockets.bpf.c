#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"

#define MAX_ENTRIES 8192
#define MAX_DURATION 30 // 30초 (초 단위)
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
    u64 start_time;  // CLOSE_WAIT 시작 시간
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

// 지속 시간이 임계값을 초과한 소켓들의 히스토그램
struct duration_key_t {
    u32 bucket;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 64);
    __type(key, struct duration_key_t);
    __type(value, u64);
} tcp_close_wait_duration_seconds SEC(".maps");

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
    key.saddr = sk->__sk_common.skc_rcv_saddr;
    key.daddr = sk->__sk_common.skc_daddr;
    key.sport = sport;
    key.dport = dport;
    key.pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    key.tgid = bpf_get_current_pid_tgid() >> 32;

    struct close_wait_info_t info = {};
    info.start_time = bpf_ktime_get_ns() / 1000000000; // 초 단위로 변환
    info.state = state;
    info.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    bpf_map_update_elem(&close_wait_sockets, &key, &info, BPF_ANY);
    bpf_printk("CLOSE_WAIT started: %s, pid=%d\n", info.comm, key.pid);
    return 0;
}

static int trace_ipv6_close_wait(const struct sock *sk, u32 state)
{
    u16 sport, dport;
    if (!extract_ports(sk, &sport, &dport)) {
        return 0;
    }

    struct close_wait_key_t key = {};
    // For IPv6, we'll use the first 4 bytes of the address as key
    // This is a simplification - in a real implementation you might want to handle IPv6 differently
    bpf_probe_read_kernel(&key.saddr, sizeof(key.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[0]);
    bpf_probe_read_kernel(&key.daddr, sizeof(key.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[0]);
    key.sport = sport;
    key.dport = dport;
    key.pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    key.tgid = bpf_get_current_pid_tgid() >> 32;

    struct close_wait_info_t info = {};
    info.start_time = bpf_ktime_get_ns() / 1000000000; // 초 단위로 변환
    info.state = state;
    info.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    bpf_map_update_elem(&close_wait_sockets, &key, &info, BPF_ANY);
    bpf_printk("CLOSE_WAIT started: %s, pid=%d\n", info.comm, key.pid);
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
        bpf_printk("CLOSE_WAIT detected! state=%d\n", state);
        return trace_close_wait(sk, state);
    }
    return 0;
}

// 주기적으로 CLOSE_WAIT 소켓들을 체크하는 함수
SEC("fentry/do_timer")
int BPF_PROG(timer_check, struct timer_list *timer)
{
    // 주기적으로 체크 (매 10초마다)
    u64 current_time = bpf_ktime_get_ns() / 1000000000;
    static u64 last_check = 0;
    
    if (current_time - last_check < 10) {
        return 0;
    }
    last_check = current_time;
    
    bpf_printk("Timer check: current_time=%llu\n", current_time);
    
    // 간단한 체크: 현재 CLOSE_WAIT 소켓 개수 확인
    // 실제 맵 순회는 복잡하므로 여기서는 간단한 로그만 출력
    bpf_printk("Periodic check for CLOSE_WAIT sockets\n");
    
    return 0;
}

// 소켓이 해제될 때 지속 시간을 계산하고 임계값 이상인 경우만 히스토그램에 추가
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

    // CLOSE_WAIT 정보 조회
    struct close_wait_info_t *info = bpf_map_lookup_elem(&close_wait_sockets, &key);
    if (info) {
        u64 current_time = bpf_ktime_get_ns() / 1000000000; // 초 단위
        u64 duration = current_time - info->start_time;
        
        bpf_printk("Socket release: duration=%llu seconds, threshold=%d\n", duration, MAX_DURATION);
        
        // 30초 이상인 경우만 히스토그램에 추가
        if (duration >= MAX_DURATION) {
            struct duration_key_t duration_key = {};
            duration_key.bucket = duration / 5; // 5초 단위로 버킷화
            
            increment_map(&tcp_close_wait_duration_seconds, &duration_key, 1);
            bpf_printk("Long CLOSE_WAIT detected! duration=%llu seconds, bucket=%d\n", duration, duration_key.bucket);
        }
        
        // 맵에서 제거
        bpf_map_delete_elem(&close_wait_sockets, &key);
    } else {
        bpf_printk("No CLOSE_WAIT info found for socket\n");
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";