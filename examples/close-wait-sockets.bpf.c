#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#define MAX_ENTRIES 8192
#define MAX_DURATION 30 // 30초 (초 단위)

// TCP states
#define TCP_CLOSE_WAIT 8
#define TCP_CLOSE 7
#define TCP_ESTABLISHED 1
#define AF_INET 2
#define AF_INET6 10
#define UPPER_PORT_BOUND 32768

// 1. CLOSE_WAIT 소켓 카운터
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} close_wait_sock SEC(".maps");

// 2. CLOSE_WAIT 상태인 소켓 추적
struct sock_key_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000);
    __type(key, struct sock_key_t);
    __type(value, u64); // 1 = CLOSE_WAIT 상태
} close_wait_tracking SEC(".maps");

// 3. 지속 시간별 히스토그램 (30초 이상만)
struct duration_key_t {
    u32 bucket;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 64);
    __type(key, struct duration_key_t);
    __type(value, u64);
} close_wait_hist SEC(".maps");

// 헬퍼 함수들
static void increment_map_value(void *map, void *key, u64 value) {
    u64 *count = bpf_map_lookup_elem(map, key);
    if (count) {
        __sync_fetch_and_add(count, value);
    } else {
        bpf_map_update_elem(map, key, &value, BPF_ANY);
    }
}

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

static int extract_sock_info(const struct sock *sk, struct sock_key_t *key)
{
    u32 family = 0;
    if (bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family) != 0) {
        return 0;
    }
    
    if (family == AF_INET) {
        if (bpf_probe_read_kernel(&key->saddr, sizeof(key->saddr), &sk->__sk_common.skc_rcv_saddr) != 0) {
            return 0;
        }
        if (bpf_probe_read_kernel(&key->daddr, sizeof(key->daddr), &sk->__sk_common.skc_daddr) != 0) {
            return 0;
        }
    } else if (family == AF_INET6) {
        if (bpf_probe_read_kernel(&key->saddr, sizeof(key->saddr), 
                                &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[0]) != 0) {
            return 0;
        }
        if (bpf_probe_read_kernel(&key->daddr, sizeof(key->daddr), 
                                &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[0]) != 0) {
            return 0;
        }
    } else {
        return 0;
    }
    
    if (extract_ports(sk, &key->sport, &key->dport) == 0) {
        return 0;
    }
    
    return 1;
}

static int trace_close_wait_start(const struct sock *sk, u32 state)
{
    struct sock_key_t key = {};
    if (!extract_sock_info(sk, &key)) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    // 이미 추적 중인 소켓인지 확인
    u64 *existing = bpf_map_lookup_elem(&close_wait_tracking, &key);
    if (!existing) {
        // 새로운 CLOSE_WAIT 소켓 추가
        u64 value = 1;
        bpf_map_update_elem(&close_wait_tracking, &key, &value, BPF_ANY);
        
        // 카운터 증가
        u32 counter_key = 0;
        increment_map_value(&close_wait_sock, &counter_key, 1);
        
        bpf_printk("CLOSE_WAIT START: pid=%d, sport=%d, dport=%d\n", pid, key.sport, key.dport);
    }

    return 0;
}

static int trace_close_wait_end(const struct sock *sk)
{
    struct sock_key_t key = {};
    if (!extract_sock_info(sk, &key)) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    // 추적 중인 소켓인지 확인
    u64 *existing = bpf_map_lookup_elem(&close_wait_tracking, &key);
    if (existing) {
        // 추적 맵에서 제거
        bpf_map_delete_elem(&close_wait_tracking, &key);
        
        // 카운터 감소
        u32 counter_key = 0;
        u64 *pcount = bpf_map_lookup_elem(&close_wait_sock, &counter_key);
        if (pcount && *pcount > 0) {
            __sync_fetch_and_add(pcount, -1);
        }
        
        bpf_printk("CLOSE_WAIT END: pid=%d, sport=%d, dport=%d\n", pid, key.sport, key.dport);
        
        // 30초 이상 지속된 경우 히스토그램 업데이트
        struct duration_key_t duration_key = {};
        duration_key.bucket = 1; // 기본값
        increment_map_value(&close_wait_hist, &duration_key, 1);
    }
    
    return 0;
}

// TCP 상태 변경 감지
SEC("kprobe/tcp_set_state")
int tcp_set_state_probe(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    int state = (int)PT_REGS_PARM2(ctx);
    
    if (!sk) return 0;

    if (state == TCP_CLOSE_WAIT) {
        bpf_printk("CLOSE_WAIT state detected! state=%d\n", state);
        return trace_close_wait_start(sk, state);
    } else if (state == TCP_CLOSE || state == TCP_ESTABLISHED) {
        // CLOSE_WAIT에서 다른 상태로 변경
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
        return trace_close_wait_end(sk);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";