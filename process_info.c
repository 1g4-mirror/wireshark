/* capture process information userespace code.
*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2024, Prakhar Pant <prakharpant288@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <unistd.h>
#include <wsutil/wslog.h>

void* read_bpf_iter(void* arg) {
    int fd = *(int*)arg;
    char buf[4096];
    ssize_t bytes_read;

    while ((bytes_read = read(fd, buf, sizeof(buf))) > 0) {
        ssize_t written_bytes = write(STDOUT_FILENO, buf, bytes_read);
        ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR,
                          "bytes written: %ld", written_bytes);
    }

    close(fd);
    return NULL;
}