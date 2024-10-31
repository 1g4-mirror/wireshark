/* capture process information userespace code.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2024, Prakhar Pant <prakharpant288@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef EBPF_USERSPACE_H
#define EBPF_USERSPACE_H

#include "process_info.h"
#include "stdint.h"

void load_ebpf_program(int *fd_map);

int map_lookup_ebpf(int map_fd,uint32_t *key,struct process_info* pinfo);

void cleanup_ebpf(void);
#endif //EBPF_USERSPACE_H
