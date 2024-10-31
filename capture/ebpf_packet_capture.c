/* capture process information kernelspace code.
*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2024, Prakhar Pant <prakharpant288@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

// Define socket-to-process mapping BPF map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64); // Inode number
    __type(value, struct process_info); // Process info
    __uint(max_entries, 1024);
} sock_proc_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // Port combination
    __type(value, struct process_info); // Process info
    __uint(max_entries, 1024);
} socket_proc_map SEC(".maps");

struct process_info {
    __u32 pid;       // Current process ID
    __u32 ppid;      // Parent process ID
    __u32 gpid;      // Grandparent process ID
    char comm[TASK_COMM_LEN]; // Command name of the process
    char p_comm[TASK_COMM_LEN]; // Command name of the parent process
    char gp_comm[TASK_COMM_LEN]; // Command name of the grandparent process
};

// Define the section and license
char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/udp_sendmsg")
int kprobe_udp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct process_info pinfo = {};

    // Capture current PID and comm
    pinfo.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&pinfo.comm, sizeof(pinfo.comm));

    // Capture parent PID and comm
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    pinfo.ppid = BPF_CORE_READ(task, real_parent, pid);
    BPF_CORE_READ_STR_INTO(&pinfo.p_comm, task, real_parent, comm);

    // Capture grandparent PID and comm (if available)
    pinfo.gpid = BPF_CORE_READ(task, real_parent, real_parent, pid);
    BPF_CORE_READ_STR_INTO(&pinfo.gp_comm, task, real_parent, real_parent, comm);

    // Read source and destination ports
    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    dport = bpf_ntohs(dport);

    // Construct port key
    __u32 port_key = ((__u32)sport << 16) | (dport & 0xFFFF);

    // Store the mapping from port key to process info
    bpf_map_update_elem(&socket_proc_map, &port_key, &pinfo, BPF_ANY);

    return 0;
}

SEC("kprobe/udp_recvmsg")
int kprobe_udp_recvmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct process_info pinfo = {};

    // Capture current PID and comm
    pinfo.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&pinfo.comm, sizeof(pinfo.comm));

    // Capture parent PID and comm
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    pinfo.ppid = BPF_CORE_READ(task, real_parent, pid);
    BPF_CORE_READ_STR_INTO(&pinfo.p_comm, task, real_parent, comm);

    // Capture grandparent PID and comm (if available)
    pinfo.gpid = BPF_CORE_READ(task, real_parent, real_parent, pid);
    BPF_CORE_READ_STR_INTO(&pinfo.gp_comm, task, real_parent, real_parent, comm);

    // Read source and destination ports
    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    dport = bpf_ntohs(dport);

    // Construct port key
    __u32 port_key = ((__u32)sport << 16) | (dport & 0xFFFF);

    // Store the mapping from port key to process info
    bpf_map_update_elem(&socket_proc_map, &port_key, &pinfo, BPF_ANY);


    return 0;
}

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct process_info pinfo = {};

    // Capture current PID and comm
    pinfo.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&pinfo.comm, sizeof(pinfo.comm));

    // Capture parent PID and comm
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    pinfo.ppid = BPF_CORE_READ(task, real_parent, pid);
    BPF_CORE_READ_STR_INTO(&pinfo.p_comm, task, real_parent, comm);

    // Capture grandparent PID and comm (if available)
    pinfo.gpid = BPF_CORE_READ(task, real_parent, real_parent, pid);
    BPF_CORE_READ_STR_INTO(&pinfo.gp_comm, task, real_parent, real_parent, comm);

    // Read source and destination ports
    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    dport = bpf_ntohs(dport);

    // Construct port key
    __u32 port_key = ((__u32)sport << 16) | (dport & 0xFFFF);

    // Store the mapping from port key to process info
    bpf_map_update_elem(&socket_proc_map, &port_key, &pinfo, BPF_ANY);


    return 0;
}

SEC("kprobe/tcp_recvmsg")
int kprobe_tcp_recvmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct process_info pinfo = {};

    // Capture current PID and comm
    pinfo.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&pinfo.comm, sizeof(pinfo.comm));

    // Capture parent PID and comm
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    pinfo.ppid = BPF_CORE_READ(task, real_parent, pid);
    BPF_CORE_READ_STR_INTO(&pinfo.p_comm, task, real_parent, comm);

    // Capture grandparent PID and comm (if available)
    pinfo.gpid = BPF_CORE_READ(task, real_parent, real_parent, pid);
    BPF_CORE_READ_STR_INTO(&pinfo.gp_comm, task, real_parent, real_parent, comm);

    // Read source and destination ports
    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    dport = bpf_ntohs(dport);

    // Construct port key
    __u32 port_key = ((__u32)sport << 16) | (dport & 0xFFFF);

    // Store the mapping from port key to process info
    bpf_map_update_elem(&socket_proc_map, &port_key, &pinfo, BPF_ANY);


    return 0;
}

SEC("kprobe/sys_sendto")
int kprobe_sys_sendto(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct process_info pinfo = {};

    // Capture current PID and comm
    pinfo.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&pinfo.comm, sizeof(pinfo.comm));

    // Capture parent PID and comm
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    pinfo.ppid = BPF_CORE_READ(task, real_parent, pid);
    BPF_CORE_READ_STR_INTO(&pinfo.p_comm, task, real_parent, comm);

    // Capture grandparent PID and comm (if available)
    pinfo.gpid = BPF_CORE_READ(task, real_parent, real_parent, pid);
    BPF_CORE_READ_STR_INTO(&pinfo.gp_comm, task, real_parent, real_parent, comm);

    // Read source and destination ports
    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    dport = bpf_ntohs(dport);

    // Construct port key
    __u32 port_key = ((__u32)sport << 16) | (dport & 0xFFFF);

    // Store the mapping from port key to process info
    bpf_map_update_elem(&socket_proc_map, &port_key, &pinfo, BPF_ANY);


    return 0;
}

SEC("kprobe/sys_recvfrom")
int kprobe_sys_recvfrom(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct process_info pinfo = {};

    // Capture current PID and comm
    pinfo.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&pinfo.comm, sizeof(pinfo.comm));

    // Capture parent PID and comm
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    pinfo.ppid = BPF_CORE_READ(task, real_parent, pid);
    BPF_CORE_READ_STR_INTO(&pinfo.p_comm, task, real_parent, comm);

    // Capture grandparent PID and comm (if available)
    pinfo.gpid = BPF_CORE_READ(task, real_parent, real_parent, pid);
    BPF_CORE_READ_STR_INTO(&pinfo.gp_comm, task, real_parent, real_parent, comm);

    // Read source and destination ports
    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    dport = bpf_ntohs(dport);

    // Construct port key
    __u32 port_key = ((__u32)sport << 16) | (dport & 0xFFFF);

    // Store the mapping from port key to process info
    bpf_map_update_elem(&socket_proc_map, &port_key, &pinfo, BPF_ANY);


    return 0;
}

SEC("kprobe/sys_recvmsg")
int kprobe_sys_recvmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct process_info pinfo = {};

    // Capture current PID and comm
    pinfo.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&pinfo.comm, sizeof(pinfo.comm));

    // Capture parent PID and comm
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    pinfo.ppid = BPF_CORE_READ(task, real_parent, pid);
    BPF_CORE_READ_STR_INTO(&pinfo.p_comm, task, real_parent, comm);

    // Capture grandparent PID and comm (if available)
    pinfo.gpid = BPF_CORE_READ(task, real_parent, real_parent, pid);
    BPF_CORE_READ_STR_INTO(&pinfo.gp_comm, task, real_parent, real_parent, comm);

    // Read source and destination ports
    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    dport = bpf_ntohs(dport);

    // Construct port key
    __u32 port_key = ((__u32)sport << 16) | (dport & 0xFFFF);

    // Store the mapping from port key to process info
    bpf_map_update_elem(&socket_proc_map, &port_key, &pinfo, BPF_ANY);


    return 0;
}

SEC("kprobe/sys_sendmsg")
int kprobe_sys_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct process_info pinfo = {};

    // Capture current PID and comm
    pinfo.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&pinfo.comm, sizeof(pinfo.comm));

    // Capture parent PID and comm
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    pinfo.ppid = BPF_CORE_READ(task, real_parent, pid);
    BPF_CORE_READ_STR_INTO(&pinfo.p_comm, task, real_parent, comm);

    // Capture grandparent PID and comm (if available)
    pinfo.gpid = BPF_CORE_READ(task, real_parent, real_parent, pid);
    BPF_CORE_READ_STR_INTO(&pinfo.gp_comm, task, real_parent, real_parent, comm);

    // Read source and destination ports
    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    dport = bpf_ntohs(dport);

    // Construct port key
    __u32 port_key = ((__u32)sport << 16) | (dport & 0xFFFF);

    // Store the mapping from port key to process info
    bpf_map_update_elem(&socket_proc_map, &port_key, &pinfo, BPF_ANY);

    return 0;
}
