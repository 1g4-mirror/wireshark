/* test_packet-bt-dht.c
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
#include "test_packet-bt-dht.h"
#include "unittest_utils.h"

static int
dissect_packet(proto_node * tree, const char * data, const size_t length)
{
    const dissector_handle_t handle = find_dissector("bt-dht");
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

static gboolean
heur_dissect_packet(proto_node * tree, const char * data, const size_t length)
{
    heur_dtbl_entry_t * dissector_info = find_heur_dissector_by_unique_short_name(
            "bittorrent_dht_udp");
    tvbuff_t * buffer = to_buffer(data, length);
    const gboolean result = dissector_info->dissector(
            buffer,
            tree->tree_data->pinfo,
            tree,
            NULL);
    tvb_free(buffer);
    return result;
}

static const proto_node *
get_dict_value(const proto_node * node, const char * key)
{
    g_assert_true(node);
    assert_string_field(get_child_n(node, 0), NULL, key);
    const proto_node * value = get_child_n(node, 1);
    g_assert_true(value);
    return value;
}

static void
assert_terminator(const proto_node * node)
{
    g_assert_true(node);
    assert_string_field(node, "bt-dht.bencoded.list.terminator", "e");
}

static void
assert_int_entry(const proto_node * entry, const char * key, const char * value)
{
    g_assert_true(entry);
    assert_abbrev(entry, "bt-dht.bencoded.dict_entry");
    assert_string_field(get_child_n(entry, 0), NULL, key);

    // Terminator appears before the int it belongs to
    assert_terminator(get_child_n(entry, 1));
    assert_string_field(get_child_n(entry, 2), NULL, value);
}

static void
assert_string_entry(const proto_node * entry, const char * key, const char * value)
{
    g_assert_true(entry);
    assert_abbrev(entry, "bt-dht.bencoded.dict_entry");
    assert_string_field(get_child_n(entry, 0), NULL, key);
    assert_string_field(get_child_n(entry, 1), NULL, value);
}

static void
assert_dict_length(const proto_node * dict, const size_t expected_length)
{
    g_assert_true(dict);
    assert_terminator(get_child_n(dict, expected_length));
    g_assert_false(get_child_n(dict, expected_length + 1));
}

static void
assert_query(const proto_node * query,
             const char * type,
             const char * type_representation,
             const char * txid,
             const char * sender_id)
{
    assert_dict_length(query, 4);
    assert_representation(get_child_n(query, 0), "Request arguments: Dictionary...");
    assert_string_entry(get_child_n(query, 1), "q", type);
    assert_representation(get_child_n(query, 1), type_representation);
    assert_string_entry(get_child_n(query, 2), "t", txid);
    assert_string_entry(get_child_n(query, 3), "y", "q");
    assert_representation(get_child_n(query, 3), "Message type: Request");

    const proto_node * args = get_dict_value(get_child_n(query, 0), "a");
    assert_string_entry(get_child_n(args, 0), "id", sender_id);
}

static void
assert_response(const proto_node * response,
                const char * txid,
                const char * sender_id)
{
    assert_dict_length(response, 3);
    assert_representation(get_child_n(response, 0), "Response values: Dictionary...");
    assert_string_entry(get_child_n(response, 1), "t", txid);
    assert_string_entry(get_child_n(response, 2), "y", "r");
    assert_representation(get_child_n(response, 2), "Message type: Response");

    const proto_node * values = get_dict_value(get_child_n(response, 0), "r");
    assert_string_entry(get_child_n(values, 0), "id", sender_id);
}

static void
test_ping_query(void)
{
    proto_tree * tree = make_tree();

    const char data[] = "d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe";
    const int consumed = dissect_packet(tree, data, sizeof(data));
    g_assert_cmpint(consumed, ==, sizeof(data) - 1);

    const proto_node * bt_dht = tree->first_child;
    assert_query(bt_dht, "ping", "Request type: ping", "6161", "6162636465666768696a30313233343536373839");

    const proto_node * args = get_dict_value(get_child_n(bt_dht, 0), "a");
    assert_dict_length(args, 1);

    clean_tree(tree);
}

static void
test_ping_response(void)
{
    proto_tree * tree = make_tree();

    const char data[] = "d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re";
    const int consumed = dissect_packet(tree, data, sizeof(data));
    g_assert_cmpint(consumed, ==, sizeof(data) - 1);

    const proto_node * bt_dht = tree->first_child;
    assert_response(bt_dht, "6161", "6d6e6f707172737475767778797a313233343536");

    const proto_node * args = get_dict_value(get_child_n(bt_dht, 0), "r");
    assert_dict_length(args, 1);

    clean_tree(tree);
}

static void
test_find_node_query(void)
{
    proto_tree * tree = make_tree();

    const char data[] = "d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe";
    const int consumed = dissect_packet(tree, data, sizeof(data));
    g_assert_cmpint(consumed, ==, sizeof(data) - 1);

    const proto_node * bt_dht = tree->first_child;
    assert_query(bt_dht, "find_node", "Request type: find_node", "6161", "6162636465666768696a30313233343536373839");

    const proto_node * args = get_dict_value(get_child_n(bt_dht, 0), "a");
    assert_string_entry(get_child_n(args, 1), "target", "6d6e6f707172737475767778797a313233343536");
    assert_dict_length(args, 2);

    clean_tree(tree);
}

static void
test_find_node_response(void)
{
    proto_tree * tree = make_tree();

    const char data[] = "d1:rd2:id20:0123456789abcdefghij5:nodes0:e1:t2:aa1:y1:re";
    const int consumed = dissect_packet(tree, data, sizeof(data));
    g_assert_cmpint(consumed, ==, sizeof(data) - 1);

    const proto_node * bt_dht = tree->first_child;
    assert_response(bt_dht, "6161", "303132333435363738396162636465666768696a");

    const proto_node * args = get_dict_value(get_child_n(bt_dht, 0), "r");
    assert_dict_length(args, 2);

    const proto_node * nodes = get_dict_value(get_child_n(args, 1), "nodes");
    g_assert_false(get_child_n(nodes, 0));

    clean_tree(tree);
}

static void
test_get_peers_query(void)
{
    proto_tree * tree = make_tree();

    const char data[] = "d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe";
    const int consumed = dissect_packet(tree, data, sizeof(data));
    g_assert_cmpint(consumed, ==, sizeof(data) - 1);

    const proto_node * bt_dht = tree->first_child;
    assert_query(bt_dht, "get_peers", "Request type: get_peers", "6161", "6162636465666768696a30313233343536373839");

    const proto_node * args = get_dict_value(get_child_n(bt_dht, 0), "a");
    assert_string_entry(get_child_n(args, 1), "info_hash", "6d6e6f707172737475767778797a313233343536");
    assert_dict_length(args, 2);

    clean_tree(tree);
}

static void
test_get_peers_response(void)
{
    proto_tree * tree = make_tree();

    const char data[] = "d1:rd2:id20:abcdefghij01234567895:token8:aoeusnth6:valueslee1:t2:aa1:y1:re";
    const int consumed = dissect_packet(tree, data, sizeof(data));
    g_assert_cmpint(consumed, ==, sizeof(data) - 1);

    const proto_node * bt_dht = tree->first_child;
    assert_response(bt_dht, "6161", "6162636465666768696a30313233343536373839");

    const proto_node * args = get_dict_value(get_child_n(bt_dht, 0), "r");
    assert_dict_length(args, 3);

    assert_string_entry(get_child_n(args, 1), "token", "616f6575736e7468");

    const proto_node * values = get_dict_value(get_child_n(args, 2), "values");
    assert_terminator(get_child_n(values, 0));
    g_assert_false(get_child_n(values, 1));

    clean_tree(tree);
}

static void
test_announce_peer_query(void)
{
    proto_tree * tree = make_tree();

    const char data[] = "d1:ad2:id20:abcdefghij012345678912:implied_porti1e9:info_hash20:mnopqrstuvwxyz123456"
                        "4:porti6881e5:token8:aoeusnthe1:q13:announce_peer1:t2:aa1:y1:qe";
    const int consumed = dissect_packet(tree, data, sizeof(data));
    g_assert_cmpint(consumed, ==, sizeof(data) - 1);

    const proto_node * bt_dht = tree->first_child;
    assert_query(bt_dht, "announce_peer", "Request type: announce_peer", "6161", "6162636465666768696a30313233343536373839");

    const proto_node * args = get_dict_value(get_child_n(bt_dht, 0), "a");
    assert_int_entry(get_child_n(args, 1), "implied_port", "1");
    assert_string_entry(get_child_n(args, 2), "info_hash", "6d6e6f707172737475767778797a313233343536");
    assert_int_entry(get_child_n(args, 3), "port", "6881");
    assert_string_entry(get_child_n(args, 4), "token", "616f6575736e7468");
    assert_dict_length(args, 5);

    clean_tree(tree);
}

static void
test_announce_peer_response(void)
{
    proto_tree * tree = make_tree();

    const char data[] = "d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re";
    const int consumed = dissect_packet(tree, data, sizeof(data));
    g_assert_cmpint(consumed, ==, sizeof(data) - 1);

    const proto_node * bt_dht = tree->first_child;
    assert_response(bt_dht, "6161", "6d6e6f707172737475767778797a313233343536");

    const proto_node * args = get_dict_value(get_child_n(bt_dht, 0), "r");
    assert_dict_length(args, 1);

    clean_tree(tree);
}

static void
test_error_response(void)
{
    proto_tree * tree = make_tree();

    const char data[] = "d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee";
    const int consumed = dissect_packet(tree, data, sizeof(data));
    g_assert_cmpint(consumed, ==, sizeof(data) - 1);

    const proto_node * bt_dht = tree->first_child;
    assert_dict_length(bt_dht, 3);
    assert_string_entry(get_child_n(bt_dht, 1), "t", "6161");
    assert_string_entry(get_child_n(bt_dht, 2), "y", "e");
    assert_representation(get_child_n(bt_dht, 2), "Message type: Error");

    const proto_node * error = get_dict_value(get_child_n(bt_dht, 0), "e");
    assert_abbrev(error, "bt-dht.error");
    assert_representation(error, "Value: error 201, A Generic Error Ocurred");

    // Terminator appears before the int it belongs to
    assert_terminator(get_child_n(error, 0));
    assert_string_field(get_child_n(error, 1), NULL, "201");

    assert_string_field(get_child_n(error, 2), NULL, "A Generic Error Ocurred");

    clean_tree(tree);
}

static void
test_heur_accepts_ping_query(void)
{
    proto_tree * tree = make_tree();

    const char data[] = "d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe";
    const gboolean accepted = heur_dissect_packet(tree, data, sizeof(data));
    g_assert_true(accepted);
    g_assert_true(find_child(tree, "bt-dht"));

    clean_tree(tree);
}

static void
test_heur_rejects_bittorrent_packet(void)
{
    proto_tree * tree = make_tree();

    // uTorrent transport protocol SYN packet
    const char data[] = "\x41\x00\x75\x8d\xfe\xcf\x8a\x2f\x00\x00"
                        "\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00";
    const gboolean accepted = heur_dissect_packet(tree, data, sizeof(data));
    g_assert_false(accepted);

    clean_tree(tree);
}

void
add_bt_dht_tests(void)
{
    test_case_add("/bt_dht/ping_query", test_ping_query);
    test_case_add("/bt_dht/ping_response", test_ping_response);
    test_case_add("/bt_dht/find_node_query", test_find_node_query);
    test_case_add("/bt_dht/find_node_response", test_find_node_response);
    test_case_add("/bt_dht/get_peers_query", test_get_peers_query);
    test_case_add("/bt_dht/get_peers_response", test_get_peers_response);
    test_case_add("/bt_dht/announce_peer_query", test_announce_peer_query);
    test_case_add("/bt_dht/announce_peer_response", test_announce_peer_response);
    test_case_add("/bt_dht/error_response", test_error_response);

    test_case_add("/bt_dht/heur/accept_ping_query", test_heur_accepts_ping_query);
    test_case_add("/bt_dht/heur/reject_bittorrent_packet", test_heur_rejects_bittorrent_packet);
}
