/* capture process information userespace code.
*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2024, Prakhar Pant <prakharpant288@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PROCESS_INFO_H
#define PROCESS_INFO_H
#include <stdint.h>
#define TASK_COMM_LEN 16

struct process_info {
    uint32_t pid;       /* Current process ID*/
    uint32_t ppid;      /* Parent process ID*/
    uint32_t gpid;      /* Grandparent process ID*/
    char comm[TASK_COMM_LEN]; /* Command name of the process*/
    char p_comm[TASK_COMM_LEN]; /* Command name of the parent process*/
    char gp_comm[TASK_COMM_LEN]; /* Command name of the grandparent process*/
};

void* read_bpf_iter(void* arg);
#endif //PROCESS_INFO_H
