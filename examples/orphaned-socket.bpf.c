#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"

#define MAX_ENTRIES 8192
#define TCP_CLOSE 7
#define TCP_CLOSE_WAIT 8
#define TCP_FIN_WAIT1 4
#define TCP_FIN_WAIT2 5
#define TCP_LAST_ACK 9
#define AF_INET 2
#define AF_INET6 10

struct orphan_key_t {
    u32 saddr;
    u32 daddr;  
    u16 sport;
    u16 dport;
    u32 pid;
    u32 tgid;
    u32 family;  // u8 대신 u32 사용 (패딩 자동 처리)
};

struct orphan_info_t {
    u64 timestamp;
    u32 state;
    u32 orphan_count;
    char comm[16];
};

// Orphaned socket 추적 맵 (카운터로 변경)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct orphan_key_t);
    __type(value, u64);  // 구조체 대신 u64 사용
} orphaned_sockets SEC(".maps");

// 전체 orphan 통계 맵
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} orphan_stats SEC(".maps");

static int extract_socket_info(const struct sock *sk, struct orphan_key_t *key)
{
    // 소켓 포인터 검증
    if (!sk) return -1;
    
    // 안전한 메모리 읽기
    u16 sport, dport;
    u8 family;
    u32 saddr, daddr;
    
    if (bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num) != 0) {
        return -1;
    }
    if (bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport) != 0) {
        return -1;
    }
    if (bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family) != 0) {
        return -1;
    }
    
    key->sport = sport;
    key->dport = __builtin_bswap16(dport);
    key->family = family;
    
    if (family == AF_INET) {
        if (bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr) != 0) {
            return -1;
        }
        if (bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr) != 0) {
            return -1;
        }
        key->saddr = saddr;
        key->daddr = daddr;
    } else if (family == AF_INET6) {
        // IPv6의 경우 첫 4바이트만 사용 (간소화)
        if (bpf_probe_read_kernel(&saddr, sizeof(saddr), 
                                 &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[0]) != 0) {
            return -1;
        }
        if (bpf_probe_read_kernel(&daddr, sizeof(daddr), 
                                 &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[0]) != 0) {
            return -1;
        }
        key->saddr = saddr;
        key->daddr = daddr;
    }
    
    return 0;
}

// TCP 소켓이 orphan 상태가 될 때 호출
SEC("kprobe/tcp_set_state")
int track_orphan_state(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    int state = (int)PT_REGS_PARM2(ctx);
    
    if (!sk) return 0;
    
    // Orphan이 될 수 있는 상태들 확인
    if (state == TCP_CLOSE || state == TCP_FIN_WAIT1 || 
        state == TCP_FIN_WAIT2 || state == TCP_LAST_ACK) {
        
        // 소켓이 실제로 orphan인지 확인 (sk_socket이 NULL인지)
        void *sk_socket_ptr;
        if (bpf_probe_read_kernel(&sk_socket_ptr, sizeof(sk_socket_ptr), &sk->sk_socket) != 0) {
            return 0;
        }
        
        if (sk_socket_ptr == NULL) {
            struct orphan_key_t key = {};
            struct orphan_info_t info = {};
            
            if (extract_socket_info(sk, &key) != 0) {
                return 0;
            }
            
            key.pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
            key.tgid = bpf_get_current_pid_tgid() >> 32;
            
            info.timestamp = bpf_ktime_get_ns();
            info.state = state;
            bpf_get_current_comm(info.comm, sizeof(info.comm));
            
            // 전체 orphan 카운트 증가
            u32 zero = 0;
            u64 *count = bpf_map_lookup_elem(&orphan_stats, &zero);
            if (count) {
                __sync_fetch_and_add(count, 1);
                info.orphan_count = *count;
            }
            
            bpf_map_update_elem(&orphaned_sockets, &key, &info, BPF_ANY);
        }
    }
    
    return 0;
}

// 소켓이 실제로 해제될 때 orphan 카운트 감소
SEC("kprobe/__sock_release")
int track_socket_release(struct pt_regs *ctx)
{
    struct socket *socket = (struct socket *)PT_REGS_PARM1(ctx);
    
    if (!socket) return 0;
    
    struct sock *sk;
    if (bpf_probe_read_kernel(&sk, sizeof(sk), &socket->sk) != 0 || !sk) {
        return 0;
    }
    
    struct orphan_key_t key = {};
    if (extract_socket_info(sk, &key) != 0) {
        return 0;
    }
    
    key.pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    key.tgid = bpf_get_current_pid_tgid() >> 32;
    
    // orphaned_sockets 맵에서 제거
    if (bpf_map_lookup_elem(&orphaned_sockets, &key)) {
        bpf_map_delete_elem(&orphaned_sockets, &key);
        
        // 전체 orphan 카운트 감소
        u32 zero = 0;
        u64 *count = bpf_map_lookup_elem(&orphan_stats, &zero);
        if (count && *count > 0) {
            __sync_fetch_and_sub(count, 1);
        }
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";