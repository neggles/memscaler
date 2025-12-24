#include <bcc/proto.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <uapi/linux/ptrace.h>

BPF_HASH(last, struct sock *, u64);

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u64  ts_us;
    u64  skaddr;
    u32  saddr[1];
    u32  daddr[1];
    u64  span_us;
    u32  pid;
    u16  lport;
    u16  dport;
    int  oldstate;
    int  newstate;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u64  ts_us;
    u64  skaddr;
    u32  saddr[4];
    u32  daddr[4];
    u64  span_us;
    u32  pid;
    u16  lport;
    u16  dport;
    int  oldstate;
    int  newstate;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);

TRACEPOINT_PROBE(sock, inet_sock_set_state) {
    if (args->protocol != IPPROTO_TCP) {
        bpf_trace_printk("protocol %d != TCP\n", args->protocol);
        return 0;
    }

    // return value store variable we'll use later
    int ret = 0;

    // get current context pid
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID

    // sk is used as a UUID
    struct sock *sk = (struct sock *)args->skaddr;

    // lport is either used in a filter here, or later
    u16 lport = args->sport;
    // dport is either used in a filter here, or later
    u16 dport = args->dport;
    FILTER_DPORT

    // calculate delta
    u64 *tsp, delta_us;
    tsp = last.lookup(&sk);
    if (tsp == 0)
        delta_us = 0;
    else
        delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
    u16 family = args->family;

    // workaround to avoid llvm optimization which will cause context ptr args
    // modified
    int tcp_newstate = args->newstate;

    if (args->family == AF_INET) {
        // bpf_trace_printk("got AF_INET event for PID %d", pid);
        struct ipv4_data_t data4 = {
            .span_us  = delta_us,
            .oldstate = args->oldstate,
            .newstate = args->newstate,
        };
        data4.skaddr = (u64)args->skaddr;
        data4.ts_us  = bpf_ktime_get_ns() / 1000;
        __builtin_memcpy(&data4.saddr, args->saddr, sizeof(data4.saddr));
        __builtin_memcpy(&data4.daddr, args->daddr, sizeof(data4.daddr));
        data4.lport = lport;
        data4.dport = dport;
        data4.pid   = pid;

        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        ret = ipv4_events.perf_submit(args, &data4, sizeof(data4));
        if (ret != 0) {
            bpf_trace_printk("ipv4_events.perf_submit failed, ret=%d", ret);
        }
    } else if (args->family == AF_INET6) {
        // bpf_trace_printk("got AF_INET6 event for PID %d", pid);
        struct ipv6_data_t data6 = {
            .span_us  = delta_us,
            .oldstate = args->oldstate,
            .newstate = args->newstate,
        };
        data6.skaddr = (u64)args->skaddr;
        data6.ts_us  = bpf_ktime_get_ns() / 1000;
        __builtin_memcpy(&data6.saddr, args->saddr_v6, sizeof(data6.saddr));
        __builtin_memcpy(&data6.daddr, args->daddr_v6, sizeof(data6.daddr));
        data6.lport = lport;
        data6.dport = dport;
        data6.pid   = pid;
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        ret = ipv6_events.perf_submit(args, &data6, sizeof(data6));
        if (ret != 0) {
            bpf_trace_printk("ipv6_events.perf_submit failed, ret=%d", ret);
        }
    } else {
        bpf_trace_printk("got event with unknown family %d", family);
    }


    if (tcp_newstate == TCP_CLOSE) {
        last.delete(&sk);
    } else {
        u64 ts = bpf_ktime_get_ns();
        last.update(&sk, &ts);
    }

    return 0;
}
