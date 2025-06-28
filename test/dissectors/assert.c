/* assert.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "glib.h"

#include "epan/proto.h"

#include "epan/ftypes/ftypes.h"

#include "assert.h"
#include "unittest_utils.h"

void
assert_abbrev(
        const proto_node * node,
        const char * abbrev)
{
    g_assert_true(node);
    g_assert_true(abbrev);
    g_assert_cmpstr(node->finfo->hfinfo->abbrev, ==, abbrev);
}

void
assert_boolean_child(
        const proto_node * parent,
        const char * abbrev,
        bool expected)
{
    const proto_node * child = find_child(parent, abbrev);
    g_assert_true(child);
    g_assert_true(child->finfo);
    g_assert_true(child->finfo->hfinfo);
    g_assert_true(child->finfo->hfinfo->type == FT_BOOLEAN);
    g_assert_true(child->finfo->value);
    g_assert_cmpint(fvalue_get_uinteger64(child->finfo->value), ==, expected);
}

void assert_ipv4_child(
        const proto_node * parent,
        const char * abbrev,
        const char * expected)
{
    const proto_node * child = find_child(parent, abbrev);
    g_assert_true(child);
    g_assert_true(child->finfo);
    g_assert_true(child->finfo->hfinfo);
    g_assert_true(child->finfo->hfinfo->type == FT_IPv4);
    g_assert_true(child->finfo->value);
    const char * actual = fvalue_to_string_repr(wmem_packet_scope(),
                                                child->finfo->value,
                                                FTREPR_DISPLAY,
                                                BASE_NONE);
    g_assert_cmpstr(actual, ==, expected);
}

void
assert_uint_child(
        const proto_node * parent,
        const char * abbrev,
        enum ftenum type,
        uint32_t value)
{
    const proto_node * child = find_child(parent, abbrev);
    g_assert_true(child);
    assert_uint_field(child, abbrev, type, value);
}

void
assert_uint_children(
        const proto_node * parent,
        const char * abbrev,
        enum ftenum type,
        const uint32_t * values,
        size_t num_values)
{
    const proto_node * child = find_child_after(parent, abbrev, NULL);
    size_t value_index = 0;
    while (child != NULL && value_index < num_values) {
        assert_uint_field(child, abbrev, type, values[value_index]);

        child = find_child_after(parent, abbrev, child);
        value_index++;
    }

    g_assert_false(child);
    g_assert_cmpint(value_index, ==, num_values);
}

void
assert_uint_field(
        const proto_node * node,
        const char * abbrev,
        enum ftenum type,
        uint32_t value)
{
    g_assert_true(node);
    g_assert_true(node->finfo);
    g_assert_true(node->finfo->hfinfo);
    g_assert_true(node->finfo->value);

    if (abbrev) {
        assert_abbrev(node, abbrev);
    }

    g_assert_true(node->finfo->hfinfo->type == type);
    g_assert_cmpint(fvalue_get_uinteger(node->finfo->value), ==, value);
}

void
assert_string_field(
        const proto_node * node,
        const char * abbrev,
        const char * expected)
{
    g_assert_true(node);
    g_assert_true(node->finfo);
    g_assert_true(node->finfo->hfinfo);
    g_assert_true(node->finfo->value);

    if (abbrev) {
        assert_abbrev(node, abbrev);
    }

    g_assert_true(node->finfo->hfinfo->type == FT_STRING);
    g_assert_cmpstr(
            fvalue_get_string(node->finfo->value),
            ==,
            expected);
}

void
assert_representation(const proto_node * node, const char * expected)
{
    g_assert_true(node);
    g_assert_true(node->finfo);
    g_assert_true(node->finfo->rep);
    g_assert_cmpstr(node->finfo->rep->representation, ==, expected);
}
