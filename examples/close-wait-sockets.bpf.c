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

// 1. 실시간 카운터 (모든 CLOSE_WAIT 소켓) - 16자 이내
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} close_wait_total SEC(".maps");

// 2. 노드 정보를 포함한 프로세스별 카운터 - 16자 이내
struct node_process_key_t {
    u32 pid;
    u32 node_ip;      // 노드 IP
    u32 ifindex;      // 네트워크 인터페이스 인덱스
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000);
    __type(key, struct node_process_key_t);
    __type(value, u64);
} close_wait_proc SEC(".maps");

// 3. 상세 추적 (모든 CLOSE_WAIT 소켓) - 16자 이내
struct close_wait_key_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 pid;
    u32 tgid;
};

struct close_wait_info_t {
    u64 start_time;
    u32 state;
    u32 uid;
    u32 node_ip;
    u32 ifindex;
    u32 pid;  // CLOSE_WAIT을 시작한 프로세스의 PID 추가
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_DETAILED_SOCKETS);
    __type(key, struct close_wait_key_t);
    __type(value, struct close_wait_info_t);
} close_wait_sock SEC(".maps");

// 4. 지속 시간별 히스토그램 (30초 이상만) - 16자 이내
struct duration_key_t {
    u32 bucket;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 64);
    __type(key, struct duration_key_t);
    __type(value, u64);
} close_wait_hist SEC(".maps");

// 5. 30초 이상 지속된 소켓 추적 - 16자 이내
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_DETAILED_SOCKETS);
    __type(key, struct close_wait_key_t);
    __type(value, struct close_wait_info_t);
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

// 노드 IP를 가져오는 함수 (로컬 주소 기반)
static u32 get_node_ip(const struct sock *sk)
{
    u32 family = 0;
    if (bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family) != 0) {
        return 0;
    }
    
    if (family == AF_INET) {
        u32 rcv_saddr = 0;
        if (bpf_probe_read_kernel(&rcv_saddr, sizeof(rcv_saddr), &sk->__sk_common.skc_rcv_saddr) == 0) {
            return rcv_saddr;
        }
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
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u64 current_time = bpf_ktime_get_ns() / 1000000000;

    // 1. 전체 카운터 증가
    u32 total_key = 0;
    increment_map_value(&close_wait_total, &total_key, 1);

    // 2. 노드 정보를 포함한 프로세스별 카운터
    struct node_process_key_t npkey = {};
    npkey.pid = pid;
    npkey.node_ip = get_node_ip(sk);
    npkey.ifindex = get_interface_index(sk);
    
    increment_map_value(&close_wait_proc, &npkey, 1);

    // 3. 상세 추적을 위한 소켓 정보 저장
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
    key.sport = sport;
    key.dport = dport;
    key.pid = pid;
    key.tgid = tgid;

    struct close_wait_info_t info = {};
    info.start_time = current_time;
    info.state = state;
    info.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    info.node_ip = npkey.node_ip;
    info.ifindex = npkey.ifindex;
    info.pid = pid;  // CLOSE_WAIT을 시작한 프로세스의 PID 저장

    bpf_map_update_elem(&close_wait_sock, &key, &info, BPF_ANY);

    bpf_printk("CLOSE_WAIT started: pid=%d, sport=%d, dport=%d, ifindex=%d\n", 
               pid, sport, dport, npkey.ifindex);
    return 0;
}

static int trace_close_wait_end(const struct sock *sk)
{
    u16 sport, dport;
    if (!extract_ports(sk, &sport, &dport)) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u64 current_time = bpf_ktime_get_ns() / 1000000000;

    // 소켓 키 생성
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
    key.sport = sport;
    key.dport = dport;
    key.pid = pid;
    key.tgid = tgid;

    // CLOSE_WAIT 상태였던 소켓인지 확인
    struct close_wait_info_t *info = bpf_map_lookup_elem(&close_wait_sock, &key);
    if (!info) {
        return 0; // CLOSE_WAIT 상태가 아니었던 소켓
    }

    u64 duration = current_time - info->start_time;

    // 카운터들 감소
    u32 total_key = 0;
    u64 *total_count = bpf_map_lookup_elem(&close_wait_total, &total_key);
    if (total_count && *total_count > 0) {
        __sync_fetch_and_add(total_count, -1);
    }

    // 수정된 부분: CLOSE_WAIT을 시작한 원래 프로세스의 정보로 감소
    struct node_process_key_t npkey = {};
    npkey.pid = info->pid;  // CLOSE_WAIT 시작할 때의 PID 사용
    npkey.node_ip = info->node_ip;
    npkey.ifindex = info->ifindex;
    
    u64 *npcount = bpf_map_lookup_elem(&close_wait_proc, &npkey);
    if (npcount && *npcount > 0) {
        __sync_fetch_and_add(npcount, -1);
    }

    // 30초 이상 지속된 경우 히스토그램 업데이트
    if (duration >= MAX_DURATION) {
        struct duration_key_t duration_key = {};
        duration_key.bucket = duration / 5; // 5초 단위 버킷
        
        increment_map_value(&close_wait_hist, &duration_key, 1);
        
        // 장기간 지속된 소켓 정보 저장
        bpf_map_update_elem(&long_duration, &key, info, BPF_ANY);
        
        bpf_printk("Long CLOSE_WAIT detected! duration=%llu seconds, bucket=%d, pid=%d\n", 
                   duration, duration_key.bucket, pid);
    }
    
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
    
    // 맵 초기화 (첫 번째 호출 시)
    u32 total_key = 0;
    u64 *total_count = bpf_map_lookup_elem(&close_wait_total, &total_key);
    if (!total_count) {
        u64 zero = 0;
        bpf_map_update_elem(&close_wait_total, &total_key, &zero, BPF_ANY);
    }

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