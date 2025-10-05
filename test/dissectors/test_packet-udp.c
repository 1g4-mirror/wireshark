/* test_packet-udp.c
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
#include "test_packet-udp.h"
#include "unittest_utils.h"

static int
dissect_packet(proto_tree * tree, const char * data, const size_t length)
{
    const dissector_handle_t handle = find_dissector("udp");
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
test_no_payload(void)
{
    proto_tree * tree = make_tree();

    const char data[] = "\x11\x22\x33\x44\x00\x08\x55\x66";
    const int consumed = dissect_packet(tree, data, sizeof(data));
    g_assert_cmpint(consumed, ==, sizeof(data) - 1);

    const proto_node *udp = tree->first_child;
    assert_representation(udp, "User Datagram Protocol, Src Port: 4386, Dst Port: 13124");

    const uint32_t ports[] = {0x1122, 0x3344};
    assert_uint_children(udp, "udp.port", FT_UINT16, ports, sizeof(ports) / sizeof(ports[0]));
    assert_uint_child(udp, "udp.srcport", FT_UINT16, 0x1122);
    assert_uint_child(udp, "udp.dstport", FT_UINT16, 0x3344);

    assert_uint_child(udp, "udp.length", FT_UINT16, 8);
    assert_uint_child(udp, "udp.checksum", FT_UINT16, 0x5566);
    assert_uint_child(udp, "udp.checksum.status", FT_UINT8, PROTO_CHECKSUM_E_UNVERIFIED);
    assert_uint_child(udp, "udp.stream", FT_UINT32, 0);

    clean_tree(tree);
}

static void
test_length_below_minimum(void)
{
    proto_tree * tree = make_tree();

    const char data[] = "\x11\x22\x33\x44\x00\x07\x55\x66";
    const int consumed = dissect_packet(tree, data, sizeof(data));
    g_assert_cmpint(consumed, ==, sizeof(data) - 1);

    const proto_node * expert = find_child(tree, "udp.length.bad");
    assert_representation(expert, "Bad length value 7 < 8");

    clean_tree(tree);
}

void
add_udp_tests(void)
{
    test_case_add("/udp/no_payload", test_no_payload);
    test_case_add("/udp/length_below_minimum", test_length_below_minimum);
}
