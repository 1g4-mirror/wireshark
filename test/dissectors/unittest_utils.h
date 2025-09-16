/* unittest_utils.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TEST_UNITTEST_UTILS_H__
#define __TEST_UNITTEST_UTILS_H__

#include <stddef.h>

#include "glib.h"

#include "epan/proto.h"
#include "epan/tvbuff.h"

void test_case_add(const char * name, void (*testFunc)(void));
void test_case_set_up(void);
void test_case_tear_down(void);

tvbuff_t * to_buffer(const char * data, const size_t data_length);

proto_tree * make_tree(void);
void clean_tree(proto_tree * tree);

void dump_tree(const proto_node *tree);

const proto_node *
get_child_n(const proto_node * node, size_t child_index);

const proto_node *
find_child(const proto_node * node, const char * abbrev);
const proto_node *
find_child_after(const proto_node * node, const char * abbrev, const proto_node * start);

#endif
