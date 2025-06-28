/* test_packet-ip.c
 * Wireshark dissector tests
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stddef.h>

#include "glib.h"

#include "epan/packet.h"
#include "epan/proto.h"
#include "epan/tvbuff.h"

#include "assert.h"
#include "test_packet-ip.h"
#include "unittest_utils.h"

static int
dissect_packet(proto_tree * tree, const char * data, const size_t length)
{
    const dissector_handle_t handle = find_dissector("ip");
    tvbuff_t * buffer = to_buffer(data, length);
    const int result = call_dissector_only(
            handle,
            buffer,
            tree->tree_data->pinfo,
            tree,
            NULL);
    tvb_free(buffer);
    return result;
}

static void
test_ip_packet(void)
{
    proto_tree * tree = make_tree();

    const char data[] = "\x45\x00\x00\x3c\x2f\xf4\x40\x00\x40\x06"
                        "\x0c\xc5\x7f\x00\x00\x01\x7f\x00\x00\x02";
    const int consumed = dissect_packet(tree, data, sizeof(data));
    g_assert_cmpint(consumed, ==, sizeof(data) - 1);

    const proto_node * ip = tree->first_child;
    assert_ipv4_child(ip, "ip.src", "127.0.0.1");
    assert_ipv4_child(ip, "ip.dst", "127.0.0.2");

    clean_tree(tree);
}

void
add_ip_tests(void)
{
    test_case_add("/ip/packet", test_ip_packet);
}
