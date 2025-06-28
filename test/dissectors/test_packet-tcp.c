/* test_packet-tcp.c
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
#include "test_packet-tcp.h"
#include "unittest_utils.h"

static int
dissect_packet(proto_tree * tree, const char * data, const size_t length)
{
    packet_info * pinfo = tree->tree_data->pinfo;
    if (wmem_list_count(pinfo->layers) == 0) {
        wmem_list_append(pinfo->layers, GINT_TO_POINTER(
                    dissector_handle_get_protocol_index(find_dissector("ip"))));
        wmem_list_append(pinfo->layers, GINT_TO_POINTER(
                    dissector_handle_get_protocol_index(find_dissector("ip"))));
    }

    const dissector_handle_t handle = find_dissector("tcp");
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
test_initial_syn(void)
{
    proto_tree * tree = make_tree();

    const char data[] = "\xb0\x04\x11\xd7\x0d\x5f\x1e\x67\x00\x00"
                        "\x00\x00\xa0\x02\xff\xd7\xfe\x31\x00\x00"
                        "\x02\x04\xff\xd7\x04\x02\x08\x0a\x52\x13"
                        "\x0e\x43\x00\x00\x00\x00\x01\x03\x03\x07";
    const int consumed = dissect_packet(tree, data, sizeof(data));
    g_assert_cmpint(consumed, ==, sizeof(data) - 1);

    const proto_node * flags = find_child(tree, "tcp.flags");
    assert_uint_field(flags, "tcp.flags", FT_UINT16, 0x0002);
    assert_boolean_child(flags, "tcp.flags.syn", TRUE);

    clean_tree(tree);
}

static void
test_synack_only(void)
{
    proto_tree * tree = make_tree();

    const char data[] = "\x11\xd7\xb0\x04\x4e\x5f\x0a\x8a\x0d\x5f"
                        "\x1e\x68\xa0\x12\xff\xcb\xfe\x31\x00\x00"
                        "\x02\x04\xff\xd7\x04\x02\x08\x0a\x03\x92"
                        "\x53\x0d\x52\x13\x0e\x43\x01\x03\x03\x07";
    const int consumed = dissect_packet(tree, data, sizeof(data));
    g_assert_cmpint(consumed, ==, sizeof(data) - 1);

    const proto_node * flags = find_child(tree, "tcp.flags");
    assert_uint_field(flags, "tcp.flags", FT_UINT16, 0x0012);
    assert_boolean_child(flags, "tcp.flags.ack", TRUE);
    assert_boolean_child(flags, "tcp.flags.syn", TRUE);

    clean_tree(tree);
}

void
add_tcp_tests(void)
{
    test_case_add("/tcp/initial_syn", test_initial_syn);
    test_case_add("/tcp/synack_only", test_synack_only);
}
