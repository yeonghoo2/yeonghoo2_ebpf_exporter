#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "maps.bpf.h"

#define MAX_ENTRIES 8192
#define MAX_DURATION 30
#define TCP_CLOSE_WAIT 8
#define TCP_CLOSE 7
#define TCP_ESTABLISHED 1
#define AF_INET 2
#define AF_INET6 10
#define UPPER_PORT_BOUND 32768

// 1. CLOSE_WAIT 소켓 추적 맵 (소켓 포인터를 키로 사용)
struct socket_info {
    u32 pid;
    u16 sport;
    u16 dport;
    u64 start_time;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);  // 소켓 포인터를 키로 사용
    __type(value, struct socket_info);
} close_wait_sockets SEC(".maps");

// 2. CLOSE_WAIT 카운터 (정확한 카운팅을 위해)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} close_wait_sock SEC(".maps");

// 3. 지속 시간별 히스토그램
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

// 안전한 카운터 증가 함수
static void safe_increment_counter(s64 delta)
{
    u32 key = 0;
    u64 *count = bpf_map_lookup_elem(&close_wait_sock, &key);
    if (count) {
        // 언더플로우 방지
        if (delta < 0 && *count < (u64)(-delta)) {
            *count = 0;
        } else {
            *count += delta;
        }
    } else {
        // 맵에 항목이 없으면 초기화
        u64 initial = (delta > 0) ? delta : 0;
        bpf_map_update_elem(&close_wait_sock, &key, &initial, BPF_ANY);
    }
}

static int trace_close_wait_start(const struct sock *sk)
{
    u16 sport, dport;
    if (!extract_ports(sk, &sport, &dport)) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 sock_ptr = (u64)sk;
    
    // 이미 추적 중인 소켓인지 확인
    struct socket_info *existing = bpf_map_lookup_elem(&close_wait_sockets, &sock_ptr);
    if (existing) {
        // 이미 추적 중이면 중복 처리하지 않음
        return 0;
    }

    struct socket_info info = {
        .pid = pid,
        .sport = sport,
        .dport = dport,
        .start_time = bpf_ktime_get_ns()
    };

    // 소켓 정보 저장
    bpf_map_update_elem(&close_wait_sockets, &sock_ptr, &info, BPF_ANY);
    
    // 카운터 증가
    safe_increment_counter(1);
    
    bpf_printk("CLOSE_WAIT START: pid=%d, sport=%d, dport=%d, sock=%llx\n", 
               pid, sport, dport, sock_ptr);
    return 0;
}

static int trace_close_wait_end(const struct sock *sk)
{
    u64 sock_ptr = (u64)sk;
    
    // 추적 중인 소켓인지 확인
    struct socket_info *info = bpf_map_lookup_elem(&close_wait_sockets, &sock_ptr);
    if (!info) {
        // 추적하지 않던 소켓이면 무시
        return 0;
    }

    // 지속 시간 계산
    u64 duration_ns = bpf_ktime_get_ns() - info->start_time;
    u64 duration_sec = duration_ns / 1000000000ULL;

    bpf_printk("CLOSE_WAIT END: pid=%d, sport=%d, dport=%d, duration=%llu sec\n", 
               info->pid, info->sport, info->dport, duration_sec);

    // 30초 이상 지속된 경우 히스토그램 업데이트
    if (duration_sec >= 30) {
        struct duration_key_t duration_key = {};
        if (duration_sec < 60) {
            duration_key.bucket = 1; // 30-60초
        } else if (duration_sec < 300) {
            duration_key.bucket = 2; // 1-5분
        } else {
            duration_key.bucket = 3; // 5분 이상
        }
        
        // 히스토그램 업데이트를 위한 안전한 증가
        u64 *hist_count = bpf_map_lookup_elem(&close_wait_hist, &duration_key);
        if (hist_count) {
            (*hist_count)++;
        } else {
            u64 initial = 1;
            bpf_map_update_elem(&close_wait_hist, &duration_key, &initial, BPF_ANY);
        }
    }

    // 소켓 추적 정보 제거
    bpf_map_delete_elem(&close_wait_sockets, &sock_ptr);
    
    // 카운터 감소
    safe_increment_counter(-1);
    
    return 0;
}

// TCP 상태 변경 감지
SEC("kprobe/tcp_set_state")
int tcp_set_state_probe(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    int new_state = (int)PT_REGS_PARM2(ctx);
    
    if (!sk) return 0;

    // 현재 상태 읽기
    u8 current_state;
    if (bpf_probe_read_kernel(&current_state, sizeof(current_state), 
                             (const void *)&sk->__sk_common.skc_state) != 0) {
        return 0;
    }

    bpf_printk("TCP state change: %d -> %d\n", current_state, new_state);

    if (new_state == TCP_CLOSE_WAIT) {
        return trace_close_wait_start(sk);
    } else if (current_state == TCP_CLOSE_WAIT && new_state != TCP_CLOSE_WAIT) {
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