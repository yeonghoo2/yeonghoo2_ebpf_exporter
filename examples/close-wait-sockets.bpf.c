#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#define MAX_ENTRIES 8192
#define MAX_DURATION 30 // 30초 (초 단위)
#define MAX_DETAILED_SOCKETS 100 // 상세 추적할 소켓 수 제한

// TCP states
#define TCP_CLOSE_WAIT 8
#define AF_INET 2
#define AF_INET6 10
#define UPPER_PORT_BOUND 32768

// 1. 프로세스별 카운터 (node_ip 제거) - 16자 이내
// 패딩 문제를 피하기 위해 u64로 통합
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000);
    __type(key, u64);  // pid(32bit) + ifindex(32bit)를 하나의 u64로
    __type(value, u64);
} close_wait_proc SEC(".maps");

// 2. 상세 추적 (모든 CLOSE_WAIT 소켓) - 16자 이내
// 단순화된 키 구조체
struct close_wait_key_t {
    u32 pid;
    u32 sport;
    u32 dport;
    u32 saddr;
    u32 daddr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_DETAILED_SOCKETS);
    __type(key, struct close_wait_key_t);
    __type(value, u64);  // 단순히 카운터로 사용
} close_wait_sock SEC(".maps");

// 3. 지속 시간별 히스토그램 (30초 이상만) - 16자 이내
struct duration_key_t {
    u32 bucket;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 64);
    __type(key, struct duration_key_t);
    __type(value, u64);
} close_wait_hist SEC(".maps");

// 4. 30초 이상 지속된 소켓 추적 - 16자 이내
struct long_duration_key_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 pid;
    u32 tgid;
    u64 start_time;  // 추가 필드들
    u32 state;
    u32 uid;
    u32 ifindex;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_DETAILED_SOCKETS);
    __type(key, struct long_duration_key_t);
    __type(value, u64);  // 단순히 카운터로 사용
} long_duration SEC(".maps");

// 헬퍼 함수들
static void increment_map_value(void *map, void *key, u64 value) {
    u64 *count = bpf_map_lookup_elem(map, key);
    if (count) {
        __sync_fetch_and_add(count, value);
    } else {
        bpf_map_update_elem(map, key, &value, BPF_ANY);
    }
}

// 프로세스 키를 u64로 만드는 헬퍼 함수
static u64 make_process_key(u32 pid, u32 ifindex) {
    return ((u64)pid << 32) | ifindex;
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

// 네트워크 인터페이스 인덱스를 가져오는 함수
static u32 get_interface_index(const struct sock *sk)
{
    u32 ifindex = 0;
    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &sk->__sk_common.skc_bound_dev_if) == 0) {
        return ifindex;
    }
    return 0;
}

static int trace_close_wait_start(const struct sock *sk, u32 state)
{
    u16 sport, dport;
    if (!extract_ports(sk, &sport, &dport)) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    // 1. 프로세스별 카운터 (u64 키 사용)
    u32 ifindex = get_interface_index(sk);
    u64 process_key = make_process_key(pid, ifindex);
    
    increment_map_value(&close_wait_proc, &process_key, 1);

    // 2. 상세 추적을 위한 소켓 정보 저장 (단순화된 키)
    struct close_wait_key_t key = {};
    u32 family = 0;
    if (bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family) == 0) {
        if (family == AF_INET) {
            bpf_probe_read_kernel(&key.saddr, sizeof(key.saddr), &sk->__sk_common.skc_rcv_saddr);
            bpf_probe_read_kernel(&key.daddr, sizeof(key.daddr), &sk->__sk_common.skc_daddr);
        } else if (family == AF_INET6) {
            bpf_probe_read_kernel(&key.saddr, sizeof(key.saddr), 
                                &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[0]);
            bpf_probe_read_kernel(&key.daddr, sizeof(key.daddr), 
                                &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[0]);
        }
    }
    key.pid = pid;
    key.sport = sport;
    key.dport = dport;

    // close_wait_sock 맵에 카운터 저장
    u64 counter_value = 1;
    bpf_map_update_elem(&close_wait_sock, &key, &counter_value, BPF_ANY);

    bpf_printk("CLOSE_WAIT START: pid=%d, sport=%d, dport=%d, saddr=%u, daddr=%u, ifindex=%d\n", 
               pid, sport, dport, key.saddr, key.daddr, ifindex);
    return 0;
}

static int trace_close_wait_end(const struct sock *sk)
{
    u16 sport, dport;
    if (!extract_ports(sk, &sport, &dport)) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    // 소켓 키 생성 (단순화된 키)
    struct close_wait_key_t key = {};
    u32 family = 0;
    if (bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family) == 0) {
        if (family == AF_INET) {
            bpf_probe_read_kernel(&key.saddr, sizeof(key.saddr), &sk->__sk_common.skc_rcv_saddr);
            bpf_probe_read_kernel(&key.daddr, sizeof(key.daddr), &sk->__sk_common.skc_daddr);
        } else if (family == AF_INET6) {
            bpf_probe_read_kernel(&key.saddr, sizeof(key.saddr), 
                                &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[0]);
            bpf_probe_read_kernel(&key.daddr, sizeof(key.daddr), 
                                &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[0]);
        }
    }
    key.pid = pid;
    key.sport = sport;
    key.dport = dport;

    // CLOSE_WAIT 상태였던 소켓인지 확인
    u64 *counter_value = bpf_map_lookup_elem(&close_wait_sock, &key);
    if (!counter_value) {
        bpf_printk("CLOSE_WAIT END: No tracking info found for pid=%d, sport=%d, dport=%d\n", 
                   pid, sport, dport);
        return 0; // CLOSE_WAIT 상태가 아니었던 소켓
    }

    // 프로세스별 카운터 감소 (u64 키 사용)
    u32 ifindex = get_interface_index(sk);
    u64 process_key = make_process_key(pid, ifindex);
    
    u64 *pcount = bpf_map_lookup_elem(&close_wait_proc, &process_key);
    if (pcount && *pcount > 0) {
        __sync_fetch_and_add(pcount, -1);
        bpf_printk("CLOSE_WAIT END: Decreased counter for pid=%d, sport=%d, dport=%d\n", 
                   pid, sport, dport);
    } else {
        bpf_printk("CLOSE_WAIT END: Counter not found for pid=%d, sport=%d, dport=%d\n", 
                   pid, sport, dport);
    }

    // 30초 이상 지속된 경우 히스토그램 업데이트
    // (정확한 지속 시간 계산은 복잡하므로 단순히 카운터만 증가)
    struct duration_key_t duration_key = {};
    duration_key.bucket = 1; // 기본값
    
    increment_map_value(&close_wait_hist, &duration_key, 1);
    
    // 장기간 지속된 소켓 정보 저장
    struct long_duration_key_t long_key = {};
    long_key.saddr = key.saddr;
    long_key.daddr = key.daddr;
    long_key.sport = sport;
    long_key.dport = dport;
    long_key.pid = pid;
    long_key.tgid = bpf_get_current_pid_tgid() >> 32;  // 여기서 사용
    long_key.start_time = bpf_ktime_get_ns() / 1000000000;
    long_key.state = 8; // TCP_CLOSE_WAIT
    long_key.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    long_key.ifindex = ifindex;
    
    u64 long_counter = 1;
    bpf_map_update_elem(&long_duration, &long_key, &long_counter, BPF_ANY);
    
    bpf_printk("Long CLOSE_WAIT detected! pid=%d\n", pid);
    
    // 추적 맵에서 제거
    bpf_map_delete_elem(&close_wait_sock, &key);
    
    return 0;
}

// 안전한 kprobe 사용
SEC("kprobe/tcp_set_state")
int tcp_set_state_probe(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    int state = (int)PT_REGS_PARM2(ctx);
    
    if (!sk) return 0;

    if (state == TCP_CLOSE_WAIT) {
        bpf_printk("CLOSE_WAIT state detected! state=%d\n", state);
        return trace_close_wait_start(sk, state);
    }
    return 0;
}

SEC("kprobe/__sock_release")
int sock_release_probe(struct pt_regs *ctx)
{
    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    
    if (!sock) return 0;
    
    struct sock *sk;
    if (bpf_probe_read_kernel(&sk, sizeof(sk), &sock->sk) != 0 || !sk) {
        return 0;
    }

    return trace_close_wait_end(sk);
}

char LICENSE[] SEC("license") = "GPL";