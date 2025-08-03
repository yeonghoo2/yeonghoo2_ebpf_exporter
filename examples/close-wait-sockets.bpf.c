#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "maps.bpf.h"  // 표준 헬퍼 함수들 포함

#define MAX_ENTRIES 8192
#define MAX_DURATION 30 // 30초 (초 단위)

// TCP states
#define TCP_CLOSE_WAIT 8
#define TCP_CLOSE 7
#define TCP_ESTABLISHED 1
#define AF_INET 2
#define AF_INET6 10
#define UPPER_PORT_BOUND 32768

// 1. CLOSE_WAIT 소켓 카운터 (HASH 맵으로 변경)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u64);
} close_wait_sock SEC(".maps");

// 2. 지속 시간별 히스토그램 (30초 이상만)
struct duration_key_t {
    u32 bucket;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 64);
    __type(key, struct duration_key_t);
    __type(value, u64);
} close_wait_hist SEC(".maps");

static int extract_ports(const struct sock *sk, u16 *sport, u16 *dport)
{
    if (bpf_probe_read_kernel(sport, sizeof(*sport), &sk->__sk_common.skc_num) != 0) {
        return 0;
    }
    if (bpf_probe_read_kernel(dport, sizeof(*dport), &sk->__sk_common.skc_dport) != 0) {
        return 0;
    }
    *dport = __builtin_bswap16(*dport);
    if (*sport > UPPER_PORT_BOUND && *dport > UPPER_PORT_BOUND) {
        return 0;
    }
    return 1;
}

static int trace_close_wait_start(const struct sock *sk, u32 state)
{
    u16 sport, dport;
    if (!extract_ports(sk, &sport, &dport)) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    // 표준 헬퍼 함수 사용 - syscalls 예제와 동일한 방식
    u32 counter_key = 0;
    increment_map(&close_wait_sock, &counter_key, 1);
    
    bpf_printk("CLOSE_WAIT START: pid=%d, sport=%d, dport=%d\n", pid, sport, dport);
    return 0;
}

static int trace_close_wait_end(const struct sock *sk)
{
    u16 sport, dport;
    if (!extract_ports(sk, &sport, &dport)) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    // 표준 헬퍼 함수 사용 - 감소
    u32 counter_key = 0;
    increment_map(&close_wait_sock, &counter_key, -1);
    
    bpf_printk("CLOSE_WAIT END: pid=%d, sport=%d, dport=%d\n", pid, sport, dport);
    
    // 30초 이상 지속된 경우 히스토그램 업데이트
    struct duration_key_t duration_key = {};
    duration_key.bucket = 1; // 기본값
    increment_map(&close_wait_hist, &duration_key, 1);
    
    return 0;
}

// TCP 상태 변경 감지
SEC("kprobe/tcp_set_state")
int tcp_set_state_probe(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    int state = (int)PT_REGS_PARM2(ctx);
    
    if (!sk) return 0;

    bpf_printk("TCP state change: %d\n", state);

    if (state == TCP_CLOSE_WAIT) {
        bpf_printk("CLOSE_WAIT state detected! state=%d\n", state);
        return trace_close_wait_start(sk, state);
    } else if (state == TCP_CLOSE || state == TCP_ESTABLISHED) {
        // CLOSE_WAIT에서 다른 상태로 변경
        bpf_printk("State change from CLOSE_WAIT to %d\n", state);
        return trace_close_wait_end(sk);
    }
    
    return 0;
}

// 소켓 해제 감지
SEC("kprobe/__sock_release")
int sock_release_probe(struct pt_regs *ctx)
{
    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    
    if (!sock) return 0;
    
    struct sock *sk;
    if (bpf_probe_read_kernel(&sk, sizeof(sk), &sock->sk) == 0 && sk) {
        bpf_printk("sock_release: calling trace_close_wait_end\n");
        return trace_close_wait_end(sk);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";