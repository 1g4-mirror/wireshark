/* test_dissectors.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "glib.h"

#include "ws_log_defs.h"

#include "epan/addr_resolv.h"
#include "epan/epan.h"
#include "wiretap/wtap.h"
#include "wsutil/privileges.h"

#include "test_packet-bt-dht.h"
#include "test_packet-ip.h"
#include "test_packet-tcp.h"
#include "test_packet-udp.h"
#include "test_unittest_utils.h"

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    ws_log_init(NULL);
    init_process_policies();
    wtap_init(0);
    epan_init(NULL, NULL, 0);

    ws_log_set_level(LOG_LEVEL_ERROR);
    gbl_resolv_flags.maxmind_geoip = FALSE;

    add_bt_dht_tests();
    add_ip_tests();
    add_tcp_tests();
    add_udp_tests();
    add_utils_tests();

    const int ret = g_test_run();

    epan_cleanup();
    wtap_cleanup();
    return ret;
}
