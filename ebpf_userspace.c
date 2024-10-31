/* capture process information userespace code.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2024, Prakhar Pant <prakharpant288@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#if WITH_LIBBPF
#include <ebpf_userspace.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <wsutil/wslog.h>


#define BPF_LOG_SIZE 16 * 1024 * 1024
struct bpf_link *link;

void set_memlock_limit(void) {
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_DEBUG,"Failed to set RLIMIT_MEMLOCK: %s\n", g_strerror(errno));
    }

    // Debugging: Check if the limit was applied
    struct rlimit current_rlim;
    if (getrlimit(RLIMIT_MEMLOCK, &current_rlim) == 0) {
        ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_DEBUG,"Current RLIMIT_MEMLOCK: soft=%ld, hard=%ld\n",
               current_rlim.rlim_cur, current_rlim.rlim_max);
    } else {
        ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "Error getting RLIMIT_MEMLOCK: %s\n", g_strerror(errno));
    }
}

void cleanup_ebpf(void) {
    // Detach the BPF program
    if (link) {
        bpf_link__destroy(link);
        ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_INFO, "Detached BPF program and cleaned up\n");
    }
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level == LIBBPF_DEBUG) return 0; // Ignore debug-level messages
    return vfprintf(stderr, format, args);
}

struct bpf_object_open_opts open_opts = {
    .sz = sizeof(struct bpf_object_open_opts),
    .kernel_log_size = BPF_LOG_SIZE,
    .kernel_log_level = 1,
};

// Call this function when capture starts
void load_ebpf_program(int *fd_map) {
    // Set up logging
    libbpf_set_print(libbpf_print_fn);
    open_opts.kernel_log_buf = g_malloc(BPF_LOG_SIZE);
    struct bpf_object *obj;
    struct bpf_program *prog;

    set_memlock_limit();

    // Load your compiled eBPF program (typically a .o file)
    obj = bpf_object__open_file("capture/ebpf_packet_capture.o", &open_opts);
    if (libbpf_get_error(obj)) {
        ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "Error loading eBPF object file: %s\n", g_strerror(-libbpf_get_error(obj)));
        ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "Verifier log:\n%s\n", open_opts.kernel_log_buf);
    }

    if (bpf_object__load(obj)) {
        ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "Error loading eBPF program into the kernel\n");
        ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "Verifier log:\n%s\n", open_opts.kernel_log_buf);
        return;
    }

    // Find the map by its name
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "socket_proc_map");
    if (!map) {
        ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "Error finding the eBPF map by name\n");
        return;
    }

    // Get the file descriptor for the map
    *fd_map = bpf_map__fd(map);
    if (*fd_map < 0) {
        ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "Error getting the map file descriptor\n");
        return;
    }

    // Iterate over the programs in the object file and attach them to respective kprobes
    bpf_object__for_each_program(prog, obj) {
        const char *prog_name = bpf_program__name(prog);
        ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_INFO, "Program name: %s\n", prog_name);

        if (strcmp(prog_name, "bpf_tcp_connect") == 0) {
            link = bpf_program__attach(prog);
            if (!link || libbpf_get_error(link)) {
                int err = libbpf_get_error(link);
                ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "Error attaching BPF program: %s\n", g_strerror(-err));
                return;
            }
        } else if (strcmp(prog_name, "bpf_netif_receive_skb") == 0) {
            link = bpf_program__attach(prog);
            if (!link || libbpf_get_error(link)) {
                int err = libbpf_get_error(link);
                ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "Error attaching BPF program: %s\n", g_strerror(-err));
                return;
            }
        } else if (strcmp(prog_name, "bpf_sys_write") == 0) {
            link = bpf_program__attach_kprobe(prog, false, "sys_write");
            if (!link || libbpf_get_error(link)) {
                int err = libbpf_get_error(link);
                ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "Error attaching BPF program: %s\n", g_strerror(-err));
                return;
            }
        } else if (strcmp(prog_name, "handle_execve") == 0) {
            link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_execve");
            if (!link || libbpf_get_error(link)) {
                int err = libbpf_get_error(link);
                ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "Error attaching BPF program: %s\n", g_strerror(-err));
                return;
            }
        } else if (strcmp(prog_name, "kprobe_tcp_v4_connect") == 0) {
            link = bpf_program__attach_kprobe(prog, false, "tcp_v4_connect");
            if (!link || libbpf_get_error(link)) {
                int err = libbpf_get_error(link);
                ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "Error attaching kprobe: %s\n", g_strerror(-err));
                return;
            }
            ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_INFO, "Attached tcp_v4_connect_kprobe\n");
        } else if (strcmp(prog_name, "kretprobe_tcp_v4_connect") == 0) {
            link = bpf_program__attach_kprobe(prog, true, "tcp_v4_connect"); // 'true' indicates kretprobe
            if (!link || libbpf_get_error(link)) {
                int err = libbpf_get_error(link);
                ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "Error attaching kretprobe: %s\n", g_strerror(-err));
                return;
            }
        } else if (strcmp(prog_name, "kprobe_tcp_set_state") == 0) {
            link = bpf_program__attach_kprobe(prog, false, "tcp_set_state");
            if (!link || libbpf_get_error(link)) {
                int err = libbpf_get_error(link);
                ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "Error attaching kprobe to tcp_set_state: %s\n", g_strerror(-err));
                return;
            }
            ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_INFO, "Attached tcp_set_state_kprobe\n");
        } else if (strcmp(prog_name, "kprobe_udp_sendmsg") == 0) {
            link = bpf_program__attach_kprobe(prog, false, "udp_sendmsg");
            if (!link || libbpf_get_error(link)) {
                int err = libbpf_get_error(link);
                ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "Error attaching kprobe to udp_sendmsg: %s\n", g_strerror(-err));
                return;
            }
            ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_INFO, "Attached udp_sendmsg\n");
        } else if (strcmp(prog_name, "kprobe_udp_recvmsg") == 0) {
            link = bpf_program__attach_kprobe(prog, false, "udp_recvmsg");
            if (!link || libbpf_get_error(link)) {
                int err = libbpf_get_error(link);
                ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "Error attaching kprobe to udp_recvmsg: %s\n", g_strerror(-err));
                return;
            }
            ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_INFO, "Attached udp_recvmsg\n");
        } else if (strcmp(prog_name, "kprobe_tcp_close") == 0) {
            link = bpf_program__attach_kprobe(prog, false, "tcp_close");
            if (!link || libbpf_get_error(link)) {
                int err = libbpf_get_error(link);
                ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "Error attaching kprobe to tcp_close: %s\n", g_strerror(-err));
                return;
            }
            ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_INFO, "Attached tcp_close_kprobe\n");
        } else if (strcmp(prog_name, "bpf_iter_tcp") == 0) {
            link = bpf_program__attach_iter(prog, NULL);
            if (!link || libbpf_get_error(link)) {
                int err = libbpf_get_error(link);
                ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "Error attaching BPF iterator: %s\n", g_strerror(-err));
                return;
            }
            ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_INFO, "Successfully attached iter/tcp BPF program\n");

            int fd = bpf_iter_create(bpf_link__fd(link));
            if (fd < 0) {
                ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "Error creating BPF iterator\n");
                return;
            }
            read_bpf_iter(&fd);
            return;
        } else if (strcmp(prog_name, "kprobe_tcp_sendmsg") == 0) {
            link = bpf_program__attach_kprobe(prog, false, "tcp_sendmsg");
            if (!link || libbpf_get_error(link)) {
                int err = libbpf_get_error(link);
                ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "Error attaching kprobe: %s\n", g_strerror(-err));
                return;
            }
            ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_INFO, "Successfully attached kprobe_tcp_sendmsg BPF program\n");
        } else if (strcmp(prog_name, "kprobe_tcp_recvmsg") == 0) {
            link = bpf_program__attach_kprobe(prog, false, "tcp_recvmsg");
            if (!link || libbpf_get_error(link)) {
                int err = libbpf_get_error(link);
                ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "Error attaching kprobe: %s\n", g_strerror(-err));
                return;
            }
            ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_INFO, "Successfully attached kprobe_tcp_recvmsg BPF program\n");
        } else if (strcmp(prog_name, "kprobe_sys_sendto") == 0) {
            link = bpf_program__attach_kprobe(prog, false /* entry */, "__sys_sendto");
            if (!link || libbpf_get_error(link)) {
                int err = libbpf_get_error(link);
                ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "Error attaching BPF program (bpf_prog_sendto): %s\n", g_strerror(-err));
                return;
            }
            ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_INFO, "Successfully attached kprobe_sys_sendto BPF program\n");
        } else if (strcmp(prog_name, "kprobe_sys_recvfrom") == 0) {
            link = bpf_program__attach_kprobe(prog, false /* entry */, "__sys_recvfrom");
            if (!link || libbpf_get_error(link)) {
                int err = libbpf_get_error(link);
                ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "Error attaching BPF program (bpf_prog_recvfrom): %s\n", g_strerror(-err));
                return;
            }
            ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_INFO, "Successfully attached kprobe_sys_recvfrom BPF program\n");
        } else if (strcmp(prog_name, "kprobe_sys_sendmsg") == 0) {
            link = bpf_program__attach_kprobe(prog, false /* entry */, "__sys_sendmsg");
            if (!link || libbpf_get_error(link)) {
                int err = libbpf_get_error(link);
                ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "Error attaching BPF program (bpf_prog_sendmsg): %s\n", g_strerror(-err));
                return;
            }
            ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_INFO, "Successfully attached kprobe_sys_sendmsg BPF program\n");
        } else if (strcmp(prog_name, "kprobe_sys_recvmsg") == 0) {
            link = bpf_program__attach_kprobe(prog, false /* entry */, "__sys_recvmsg");
            if (!link || libbpf_get_error(link)) {
                int err = libbpf_get_error(link);
                ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "Error attaching BPF program (bpf_prog_recvmsg): %s\n", g_strerror(-err));
                return;
            }
            ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_INFO, "Successfully attached kprobe_sys_recvmsg BPF program\n");
        } else {
            ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR, "link cannot be created as program: %s doesn't match any option.", prog_name);
        }
    }
    ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_INFO, "Program loaded and attached. Press Ctrl+C to exit.\n");
    g_free(open_opts.kernel_log_buf);
}

int map_lookup_ebpf(int map_fd,uint32_t *key,struct process_info* pinfo) {
    return bpf_map_lookup_elem(map_fd, key, pinfo);
}

#endif