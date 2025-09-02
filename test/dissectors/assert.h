/* assert.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TEST_ASSERT_H__
#define __TEST_ASSERT_H__

void assert_abbrev(
        const proto_node * node,
        const char * abbrev);

void assert_boolean_child(
        const proto_node * parent,
        const char * abbrev,
        bool expected);

void assert_ipv4_child(
        const proto_node * parent,
        const char * abbrev,
        const char * expected);

void assert_uint_child(
        const proto_node * parent,
        const char * abbrev,
        enum ftenum type,
        uint32_t value);
void assert_uint_children(
        const proto_node * parent,
        const char * abbrev,
        enum ftenum type,
        const uint32_t * values,
        size_t num_values);
void assert_uint_field(
        const proto_node * node,
        const char * abbrev,
        enum ftenum type,
        uint32_t value);

void assert_string_field(
        const proto_node * node,
        const char * abbrev,
        const char * expected);

void assert_representation(
        const proto_node * node,
        const char * expected);

#endif
