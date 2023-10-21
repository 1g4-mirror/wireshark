/* unittest_utils.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stddef.h>
#include <stdio.h>

#include "glib.h"

#include "epan/column.h"
#include "epan/column-info.h"
#include "epan/column-utils.h"
#include "epan/proto.h"
#include "epan/tvbuff.h"
#include "epan/wmem_scopes.h"

#include "wiretap/wtap.h"

#include "unittest_utils.h"

struct EmptyFixture {};

static void
fixture_set_up(struct EmptyFixture * fixture _U_, gconstpointer user_data _U_)
{
    test_case_set_up();
}

static void
fixture_tear_down(struct EmptyFixture * fixture _U_, gconstpointer user_data _U_)
{
    test_case_tear_down();
}

static void
test_wrapper(struct EmptyFixture * fixture _U_, gconstpointer user_data _U_)
{
    void (*testFunc)(void) = user_data;
    testFunc();
}

void
test_case_add(const char * name, void (*testFunc)(void))
{
    g_test_add(name, struct EmptyFixture, testFunc, fixture_set_up,
               test_wrapper, fixture_tear_down);
}

void
test_case_set_up(void)
{
    wmem_enter_file_scope();
    wmem_enter_packet_scope();
}

void
test_case_tear_down(void)
{
    wmem_leave_packet_scope();
    wmem_leave_file_scope();
}

tvbuff_t *
to_buffer(const char * data, const size_t data_length)
{
    g_assert_cmpint(data_length, >, 0);
    g_assert_cmpint(data_length, <=, G_MAXINT);
    return tvb_new_real_data(data, (guint)(data_length - 1), (gint)(data_length - 1));
}

proto_tree *
make_tree(void)
{
    packet_info * pinfo = wmem_new(wmem_packet_scope(), packet_info);
    memset(pinfo, 0, sizeof(*pinfo));
    pinfo->pool = wmem_packet_scope();
    pinfo->layers = wmem_list_new(wmem_packet_scope());
    pinfo->num = 1;

    column_info * cinfo = wmem_new(wmem_packet_scope(), column_info);
    build_column_format_array(cinfo, 7, TRUE);
    col_init(cinfo, NULL);
    pinfo->cinfo = cinfo;

    wtap_rec rec;
    wtap_rec_init(&rec);

    pinfo->fd = wmem_new(wmem_packet_scope(), frame_data);
    frame_data_init(pinfo->fd, 0, &rec, 0, 0);

    wtap_rec_cleanup(&rec);

    proto_tree * tree = proto_tree_create_root(pinfo);
    proto_tree_set_visible(tree, TRUE);
    return tree;
}

void
clean_tree(proto_tree * tree)
{
    frame_data_destroy(tree->tree_data->pinfo->fd);
    g_slist_free(tree->tree_data->pinfo->proto_data);
    col_cleanup(tree->tree_data->pinfo->cinfo);
    proto_tree_free(tree);
}

static void
dump_tree_nested(const proto_node *tree, unsigned int level)
{
    for (unsigned int i = 0; i < level; i++) {
        fprintf(stderr, " ");
    }

    fprintf(stderr, "Node");
    if (tree->finfo) {
        fprintf(stderr, ", offset %i, length %i", tree->finfo->start, tree->finfo->length);
        if (tree->finfo->hfinfo) {
            fprintf(stderr, ", abbrev=%s", tree->finfo->hfinfo->abbrev);
        }
        if (tree->finfo->hfinfo) {
            fprintf(stderr, ", name=\"%s\"", tree->finfo->hfinfo->name);
        }
        if (tree->finfo->rep) {
            fprintf(stderr, ", rep=\"%s\"", tree->finfo->rep->representation);
        }
    }

    fprintf(stderr, "\n");

    proto_node * child = tree->first_child;
    while (child != NULL) {
        dump_tree_nested(child, level + 1);
        child = child->next;
    }
}

void
dump_tree(const proto_node *tree)
{
    dump_tree_nested(tree, 0);
}

const proto_node *
get_child_n(const proto_node * node, size_t child_index)
{
    g_assert_true(node);
    const proto_node * ret = node->first_child;
    for (size_t i = 0; i < child_index; i++) {
        g_assert_true(ret);
        ret = ret->next;
    }
    return ret;
}

const proto_node *
find_child(const proto_node * node, const char * abbrev)
{
    g_assert(node);
    g_assert(abbrev);

    const proto_node * ret = NULL;
    const proto_node * child = node->first_child;
    while (child) {
        if (strcmp(child->finfo->hfinfo->abbrev, abbrev) == 0) {
            g_assert(ret == NULL);
            ret = child;
        }

        const proto_node * child_result = find_child(child, abbrev);
        if (child_result) {
            g_assert(ret == NULL);
            ret = child_result;
        }

        child = child->next;
    }

    return ret;
}

const proto_node *
find_child_after(const proto_node * node, const char * abbrev, const proto_node * start)
{
    g_assert(node);
    g_assert(abbrev);

    bool found_start = (start == NULL);
    const proto_node * child = node->first_child;
    while (child) {
        if (found_start && strcmp(child->finfo->hfinfo->abbrev, abbrev) == 0) {
            return child;
        }
        if (child == start) {
            found_start = true;
        }

        const proto_node * child_result = find_child_after(child, abbrev, found_start ? NULL : start);
        if (child_result) {
            return child_result;
        }

        child = child->next;
    }

    return NULL;
}
