/* dissector_table_test.c
 * Standalone program to test dissector lookup tables
 *
 * For now, we only test register_dissector_table() and
 * dissector_get_*_handle() since they're relatively straightforward
 * to test in isolation.
 *
 * The dissector_try_*() functions are much harder to test in isolation
 * because they assume an actual packet with a complete packet_info,
 * and completely loaded prefs to get prefs.gui_max_tree_depth to check
 * against that packet_info, and so on down the house of cards until we
 * essentially recreate tshark.
 *
 * As with most test suites in Wireshark, this is incomplete.
 * Improvements are welcomed.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <wireshark.h>

#include <epan/wmem_scopes.h>
#include <epan/packet.h>

/*** Fake dissector setup ***/

static dissector_handle_t dummy_handle,
                          handle_ret_1,
                          handle_ret_0;
static int proto_dummy;

#define STUB_DISSECTOR(name,ret_val) \
    int name(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) { return ret_val; }

/* This stub represents the dissector which has dissector lookup tables. */
STUB_DISSECTOR(dissect_dummy, 1);

/* The remaining stubs represent sub-dissectors that have registered in
 * the dissector lookup tables of the dummy dissector.
 * (In this case it's for the same protocol but that often isn't the case.)
 */
STUB_DISSECTOR(subdissector_ret_1, 1);
STUB_DISSECTOR(subdissector_ret_0, 0);

/*** Unit test functions ***/

void test_uint8(void)
{
    dissector_handle_t a_handle;

    dissector_table_t uint8_table = register_dissector_table(
                                        "uint8_test", "test FT_UINT8",
                                        proto_dummy, FT_UINT8, BASE_DEC);

    /* dissector_get_uint_handle */
    dissector_add_uint("uint8_test", 3, handle_ret_1);
    a_handle = dissector_get_uint_handle(uint8_table, 3);
    g_assert_true(a_handle == handle_ret_1);

    a_handle = dissector_get_uint_handle(uint8_table, 4);
    g_assert_true(a_handle == NULL);

    /* adding an entry for a value that already exists */
    dissector_add_uint("uint8_test", 3, handle_ret_0);
    a_handle = dissector_get_uint_handle(uint8_table, 3);
    g_assert_true(a_handle == handle_ret_0);
}

void test_string(void)
{
    dissector_handle_t a_handle;

    dissector_table_t str_table = register_dissector_table(
                                        "string_test", "test FT_STRING",
                                        proto_dummy, FT_STRING, STRING_CASE_SENSITIVE);

    /* dissector_get_string_handle */
    dissector_add_string("string_test", "foo", handle_ret_1);
    a_handle = dissector_get_string_handle(str_table, "foo");
    g_assert_true(a_handle == handle_ret_1);

    a_handle = dissector_get_string_handle(str_table, "bar");
    g_assert_true(a_handle == NULL);

    /* adding an entry for a value that already exists */
    dissector_add_string("string_test", "foo", handle_ret_0);
    a_handle = dissector_get_string_handle(str_table, "foo");
    g_assert_true(a_handle == handle_ret_0);
}

void test_guid(void)
{
    dissector_handle_t a_handle;

    /* These are separate so we can tell they aren't being compared
     * by simple pointer */
    guid_key enter_guid = {
        .guid = {0x01234567, 0x89AB, 0xCDEF, {1, 2, 3, 4, 5, 6, 7, 8}},
        .ver = 0,
    };
    guid_key seek_guid = {
        .guid = {0x01234567, 0x89AB, 0xCDEF, {1, 2, 3, 4, 5, 6, 7, 8}},
        .ver = 0,
    };
    guid_key bad_guid = {
        .guid = {0xFEDCBA98, 0x7654, 0x3210, {9, 8, 7, 6, 5, 4, 3, 2}},
        .ver = 0,
    };

    dissector_table_t guid_table = register_dissector_table(
                                        "guid_test", "test FT_GUID",
                                        proto_dummy, FT_GUID, BASE_NONE);

    /* dissector_get_guid_handle */
    dissector_add_guid("guid_test", &enter_guid, handle_ret_1);
    a_handle = dissector_get_guid_handle(guid_table, &seek_guid);
    g_assert_true(a_handle == handle_ret_1);

    a_handle = dissector_get_guid_handle(guid_table, &bad_guid);
    g_assert_true(a_handle == NULL);

    /* adding an entry for a value that already exists */
    dissector_add_guid("guid_test", &enter_guid, handle_ret_0);
    a_handle = dissector_get_guid_handle(guid_table, &seek_guid);
    g_assert_true(a_handle == handle_ret_0);
}

/*** Main routine to perform the tests ***/

int main(int argc, char **argv)
{
    int ret;

    wmem_init_scopes();
    packet_init();

    proto_dummy = proto_register_protocol("Dissector table test proto", "ddtest", "dttest");
    dummy_handle = register_dissector("dissector_table_test", dissect_dummy, proto_dummy);
    handle_ret_1 = register_dissector("subdissector_ret_1", subdissector_ret_1, proto_dummy);
    handle_ret_0 = register_dissector("subdissector_ret_0", subdissector_ret_0, proto_dummy);

    g_test_init(&argc, &argv, NULL);

    /* register_dissector_table() and
     * find_uint_dtbl_entry() (from dissector_get_uint_handle, ...)
     * use the same code path for FT_UINT8, FT_UINT16, FT_UINT24, FT_UINT32
     */
    g_test_add_func("/dissector_table/uint8", test_uint8);

    /* register_dissector_table() and
     * find_string_dtbl_entry() (from dissector_get_string_handle, ...)
     * use the same code path for FT_STRING, FT_STRINGZ, FT_STRINGZPAD, FT_STRINGZTRUNC
     */
    g_test_add_func("/dissector_table/string", test_string);

    /* FT_GUID has unique code paths */
    g_test_add_func("/dissector_table/guid", test_guid);

    ret = g_test_run();

    packet_cleanup();
    wmem_cleanup_scopes();
    return ret;
}
