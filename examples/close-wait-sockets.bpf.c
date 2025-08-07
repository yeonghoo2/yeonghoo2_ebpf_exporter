// close-wait 상태 소켓 추적
// node 레벨에서는 metric으로 노출
// 카디널리티 문제로 pid, tid를 map에 저장한 메트릭은 노출하지않음
// 노드의 close-wait 소켓 수를 모니터링하다가 이상한 점이 발생하는 노드에는 직접 접속해서 bpftool로 확인

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "maps.bpf.h"

// TCP 상태 상수 정의
#define TCP_CLOSE_WAIT 8
#define TCP_CLOSE 7
#define TCP_ESTABLISHED 1

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

// 3. 현재 활성화된 CLOSE_WAIT 소켓 추적 (정확한 카운팅용)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);  // 소켓 포인터를 키로 사용
    __type(value, u32); // 단순히 존재 여부만 추적
} active_close_wait_sockets SEC(".maps");

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

static int get_current_process_info(u32 *pid, u32 *tgid)
{
    struct task_struct *current = (struct task_struct *)bpf_get_current_task();
    if (!current) {
        // fallback
        u64 pid_tgid = bpf_get_current_pid_tgid();
        *pid = (u32)pid_tgid;
        *tgid = (u32)(pid_tgid >> 32);
        return 0;
    }
    
    // 현재 태스크에서 PID와 TGID 직접 읽기
    if (bpf_probe_read_kernel(pid, sizeof(*pid), &current->pid) != 0) {
        *pid = 0;
    }
    if (bpf_probe_read_kernel(tgid, sizeof(*tgid), &current->tgid) != 0) {
        *tgid = 0;
    }
    
    return 1;
}

static int trace_close_wait_start(const struct sock *sk)
{
    u16 sport, dport;
    if (!extract_ports(sk, &sport, &dport)) {
        return 0;
    }

    // 현재 프로세스 정보 가져오기
    u32 pid, tgid;
    get_current_process_info(&pid, &tgid);
    
    u64 sock_ptr = (u64)sk;
    
    // 이미 추적 중인 소켓인지 확인
    struct socket_info *existing = bpf_map_lookup_elem(&close_wait_sockets, &sock_ptr);
    if (existing) {
        return 0;
    }

    // active_close_wait_sockets에 추가
    u32 dummy = 1;
    bpf_map_update_elem(&active_close_wait_sockets, &sock_ptr, &dummy, BPF_ANY);

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

    // active_close_wait_sockets에서 제거
    bpf_map_delete_elem(&active_close_wait_sockets, &sock_ptr);

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

    // bpf_printk("TCP state change: %d -> %d, sock=%llx\n", current_state, new_state, (u64)sk);

    if (new_state == TCP_CLOSE_WAIT) {
        bpf_printk("Entering CLOSE_WAIT state: sock=%llx\n", (u64)sk);
        return trace_close_wait_start(sk);
    } else if (current_state == TCP_CLOSE_WAIT && new_state != TCP_CLOSE_WAIT) {
        bpf_printk("Leaving CLOSE_WAIT state: sock=%llx\n", (u64)sk);
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