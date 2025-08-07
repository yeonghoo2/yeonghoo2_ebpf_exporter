// close-wait 상태 소켓 추적
// node 레벨에서는 metric으로 노출
// 카디널리티 문제로 pid, tid를 map에 저장한 메트릭은 노출하지않음
// close-wait 상태 소켓 수가 이상한 노드가 발생하면 접속해서 확인하기

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "maps.bpf.h"

// TCP 상태 상수 정의
#define TCP_CLOSE_WAIT 8

// 1. CLOSE_WAIT 소켓 추적 맵 (소켓 포인터를 키로 사용)
struct socket_info {
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
    if (!sk) return 0;
    
    if (bpf_probe_read_kernel(sport, sizeof(*sport), &sk->__sk_common.skc_num) != 0) {
        return 0;
    }
    if (bpf_probe_read_kernel(dport, sizeof(*dport), &sk->__sk_common.skc_dport) != 0) {
        return 0;
    }
    *dport = __builtin_bswap16(*dport);
    
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
    
    u64 sock_ptr = (u64)sk;
    
    // 이미 추적 중인 소켓인지 확인
    struct socket_info *existing = bpf_map_lookup_elem(&close_wait_sockets, &sock_ptr);
    if (existing) {
        return 0;
    }

    struct socket_info info = {
        .sport = sport,
        .dport = dport,
        .start_time = bpf_ktime_get_ns()
    };

    // 소켓 정보 저장
    bpf_map_update_elem(&close_wait_sockets, &sock_ptr, &info, BPF_ANY);
    
    // 카운터 증가
    safe_increment_counter(1);
    
    return 0;
}

static int trace_close_wait_end(const struct sock *sk)
{
    u64 sock_ptr = (u64)sk;
    
    // 추적 중인 소켓인지 확인
    struct socket_info *info = bpf_map_lookup_elem(&close_wait_sockets, &sock_ptr);
    if (!info) {
        return 0;
    }

    // 지속 시간 계산
    u64 duration_ns = bpf_ktime_get_ns() - info->start_time;
    u64 duration_sec = duration_ns / 1000000000ULL;

    // 30초 이상 지속된 경우 히스토그램 업데이트
    if (duration_sec >= 30) {
        struct duration_key_t duration_key = {};
        u32 bucket = (duration_sec >= 300) ? 3 : 
                     (duration_sec >= 60) ? 2 : 1;
        duration_key.bucket = bucket;
        
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
        // 소켓이 해제될 때도 close_wait 상태였다면 추적 종료
        return trace_close_wait_end(sk);
    }
    return 0;
}

// 소켓이 완전히 해제될 때도 추적 종료
SEC("kprobe/sock_put")
int sock_put_probe(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    return trace_close_wait_end(sk);
}

char LICENSE[] SEC("license") = "GPL";