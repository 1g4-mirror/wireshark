/* test_unittest_utils.c
 * Wireshark dissector tests
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "epan/proto.h"

#include "test_unittest_utils.h"
#include "unittest_utils.h"

static proto_node *
make_node(const char * abbrev)
{
    header_field_info * hfinfo = wmem_new(wmem_packet_scope(), header_field_info);
    hfinfo->abbrev = abbrev;

    proto_node * node = wmem_new(wmem_packet_scope(), proto_node);
    memset(node, 0, sizeof(*node));
    node->finfo = wmem_new(wmem_packet_scope(), field_info);
    node->finfo->hfinfo = hfinfo;

    return node;
}

static void
test_find_in_empty_tree(void)
{
    proto_node * head = make_node("foo");
    g_assert_true(NULL == find_child_after(head, "bar", NULL));
}

static void
test_find_first_node_in_tree(void)
{
    proto_node * head = make_node("bar");
    proto_node * target = make_node("foo");
    head->first_child = target;
    g_assert_true(target == find_child_after(head, "foo", NULL));
}

static void
test_find_first_of_multiple(void)
{
    proto_node * head = make_node("bar");
    proto_node * target = make_node("foo");
    proto_node * second = make_node("foo");

    head->first_child = target;
    target->next = second;

    g_assert_true(target == find_child_after(head, "foo", NULL));
}

static void
test_find_sibling_of_first_match(void)
{
    proto_node * head = make_node("bar");
    proto_node * first = make_node("foo");
    proto_node * target = make_node("foo");

    head->first_child = first;
    first->next = target;

    g_assert_true(target == find_child_after(head, "foo", first));
}

static void
test_find_child_of_first_match(void)
{
    proto_node * head = make_node("bar");
    proto_node * first = make_node("foo");
    proto_node * target = make_node("foo");

    head->first_child = first;
    first->first_child = target;

    g_assert_true(target == find_child_after(head, "foo", first));
}

void
add_utils_tests(void)
{
    test_case_add("/utils/find_child_after/empty_tree", test_find_in_empty_tree);
    test_case_add("/utils/find_child_after/first_node", test_find_first_node_in_tree);
    test_case_add("/utils/find_child_after/first_of_multiple", test_find_first_of_multiple);
    test_case_add("/utils/find_child_after/sibling_of_first_match", test_find_sibling_of_first_match);
    test_case_add("/utils/find_child_after/child_of_first_match", test_find_child_of_first_match);
}
