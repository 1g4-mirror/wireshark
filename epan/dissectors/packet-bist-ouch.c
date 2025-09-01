/* packet-bist-ouch.c
 * Routines for BIST-OUCH dissection
 * Copyright 2025, Sadettin Er <sadettin.er@b-ulltech.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
// -----------------------------------------------------------------------------
//
//  Documentation:
//  https://www.borsaistanbul.com/files/OUCH_ProtSpec_BIST_va2413.pdf

#include "config.h"
#include <wireshark.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/column-utils.h>

#include <glib.h>
#include <epan/address.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/value_string.h>
#include <wsutil/wmem/wmem.h>
#include <wsutil/wmem/wmem_map.h>

#define PNAME  "BIST OUCH"
#define PSHORT "BIST-OUCH"
#define PFILT  "bist_ouch"

static bool bist_ouch_show_decimal_price = false;
static dissector_handle_t bist_ouch_handle;
static bool bist_ouch_enable_orderbook_tracking = true;
static bool bist_ouch_show_order_index_in_info = false;
static bool bist_ouch_show_global_index_in_info = false;
static bool bist_ouch_show_group_id_in_info = false;
static bool bist_ouch_show_match_in_info = true;
static int ett_bist_ouch_orderbook;
static int hf_ob_initial_token;
static int hf_ob_replacement_token;
static int hf_ob_previous_token;
static int hf_ob_group_index;
static int hf_ob_group_size;
static int hf_ob_is_inbound;
static int hf_ob_global_index;
static int hf_ob_group_id;
static expert_field ei_ob_prev_unmapped;
static expert_field ei_ob_eot_not_initial; /* warn when EOT != initial token */

typedef struct order_group_t_ {
    struct order_group_t_ *parent;

    const char *initial_token;

    uint64_t     first_frame;
    uint32_t     next_index;
    uint32_t     total;

    uint32_t     group_id;
} order_group_t;

static wmem_map_t *g_token_to_group = NULL;

typedef struct {
    uint32_t last_inbound_global;
    uint32_t last_outbound_global;
    uint32_t last_inbound_frame;
    uint32_t last_outbound_frame;
} stream_session_tracking_t;

static unsigned ob_stream_key_hash(const void *key)
{
    uint64_t key_val = (uint64_t)(uintptr_t)key;
    return (unsigned)(key_val ^ (key_val >> 32));
}

static int ob_stream_key_equal(const void *a, const void *b)
{
    return (uint64_t)(uintptr_t)a == (uint64_t)(uintptr_t)b;
}

static unsigned ob_str_hash(const void *key)            { return key ? g_str_hash(key) : 0; }
static int ob_str_equal(const void *a, const void *b)
{
    if (a == b) return 1;
    if (!a || !b) return 0;
    return g_str_equal(a, b) ? 1 : 0;
}

typedef struct ob_frame_idx_t_ {
    uint32_t        index;
    uint32_t        global_index;
    order_group_t  *group;
    uint32_t        match_id;
} ob_frame_idx_t;

static wmem_map_t *g_frame_to_index = NULL;
static wmem_allocator_t *g_current_file_scope = NULL;
static uint32_t g_next_global_index;
static uint32_t g_next_group_id;

/* Stream-based session tracking maps (replaces string-based session keys) */
static wmem_map_t *g_stream_session_tracking = NULL;
static wmem_map_t *g_frame_to_partner_global = NULL;

static void   bist_ouch_reset_state(void);
static void   ob_lazy_reset_on_new_capture(packet_info *pinfo _U_);
static bool   ob_is_u_outbound(tvbuff_t *tvb);
static uint64_t ob_make_stream_token_key(packet_info *pinfo, const char *token);
static stream_session_tracking_t* ob_get_stream_tracking(packet_info *pinfo, const char *token);
static order_group_t* ob_find_root(order_group_t *g);
static order_group_t* ob_union_groups(order_group_t *a, order_group_t *b);
static order_group_t* ob_lookup_group(wmem_map_t *token_map, const char *token);
static order_group_t* ob_ensure_group_for_token(wmem_map_t *token_map, const char *token, uint64_t frame_num);
static void           ob_map_token_to_group(wmem_map_t *token_map, const char *token, order_group_t *g);
static const char* ob_get_ascii_token(tvbuff_t *tvb, int offset, int len, wmem_allocator_t *scope);

typedef struct ob_token_info_t_ {
    const char *iot;   /* initial inbound token (or token carried) */
    const char *rot;   /* replacement token if present */
    const char *prev;  /* previous replacement token if present */
    bool has_iot;
    bool has_rot;
    bool has_prev;
    bool is_inbound;   /* direction */
    uint8_t type;
} ob_token_info_t;

static void ob_extract_token_info(tvbuff_t *tvb, packet_info *pinfo, ob_token_info_t *ti);
static void ob_track_and_annotate(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pt, proto_item *root_item);

/* Value strings */
static const value_string ouch_msg_types[] = {
    { 'O', "Enter Order" }, /* inbound */
    { 'U', "Replace/Order Replaced" }, /* inbound/outbound */
    { 'X', "Cancel Order" }, /* inbound */
    { 'Y', "Cancel by Order ID" }, /* inbound */
    { 'Q', "Mass Quote" }, /* inbound */
    { 'A', "Order Accepted" }, /* outbound */
    { 'J', "Order Rejected" }, /* outbound */
    { 'C', "Order Canceled" }, /* outbound */
    { 'E', "Order Executed" }, /* outbound */
    { 'K', "Mass Quote Ack" }, /* outbound */
    { 'R', "Mass Quote Rejection" }, /* outbound */
    {  0, NULL }
};

static const value_string ouch_side_vals[] = {
    { 'B', "Buy" },
    { 'S', "Sell" },
    { 'T', "Short" },
    { 0, NULL }
};

static const value_string ouch_tif_vals[] = {
    { 0, "Day" },
    { 3, "IOC" },
    { 4, "FOK" },
    { 0, NULL }
};

static const value_string ouch_openclose_vals[] = {
    { 0, "Default/No change" },
    { 1, "Open"  },
    { 2, "Close/Net" },
    { 4, "Default for account" },
    { 0, NULL }
};

static const value_string ouch_client_cat_vals[] = {
    { 1,  "Client" },
    { 2,  "House" },
    { 7,  "Fund" },
    { 9,  "Investment Trust" },
    { 10, "Primary Dealer Govt" },
    { 11, "Primary Dealer Corp" },
    { 12, "Portfolio Mgmt Company" },
    { 0,  NULL }
};

static const value_string ouch_cancel_reason_vals[] = {
    { 1,  "Canceled by user/other user" },
    { 3,  "Trade" },
    { 4,  "Inactivate" },
    { 5,  "Replaced by User" },
    { 6,  "New" },
    { 8,  "Converted by System" },
    { 9,  "Canceled by System" },
    { 10, "Canceled by Proxy" },
    { 11, "Bait Recalculated" },
    { 12, "Triggered by System" },
    { 13, "Refreshed by System" },
    { 15, "Canceled by System Limit Change" },
    { 17, "Linked Leg Canceled" },
    { 18, "Linked Leg Modified" },
    { 19, "Expired" },
    { 20, "Canceled Due to ISS" },
    { 21, "Inactivated Due to ISS" },
    { 23, "Inactivated Due to Purge" },
    { 24, "Inactivated Day Order" },
    { 25, "Inactivated Due to DeList" },
    { 26, "Inactivated Due to Expiry" },
    { 27, "Inactivated Due to Outside Limits" },
    { 28, "Transfer of Ownership" },
    { 29, "New Inactive" },
    { 30, "Reloaded" },
    { 31, "Reloaded Intraday" },
    { 34, "Canceled After Auction" },
    { 35, "Inactivated Due to Outside Price Limits" },
    { 36, "Activated Due to Outside Limits" },
    { 37, "Trigger on Session Order Triggered" },
    { 39, "Undisclosed Qty Order Converted" },
    { 40, "Inactivated Due to Order Value" },
    { 41, "System Delta Protection" },
    { 42, "System Quantity Protection" },
    { 43, "Internal Crossing Delete" },
    { 44, "Participant Block on Market" },
    { 45, "Inactivated Due to Participant Block" },
    { 46, "Order deleted due to SMP" },
    { 52, "Paused" },
    { 53, "Activated Paused Order" },
    { 56, "Linked Leg Activated" },
    { 115, "PTRM misc" },
    { 116, "PTRM user limits auto" },
    { 117, "PTRM user limits manual" },
    { 118, "PTRM market limits" },
    { 119, "PTRM investor limits" },
    { 120, "PTRM margin breach" },
    { 121, "PTRM participant suspension" },
    { 122, "PTRM mra suspension" },
    { 123, "PTRM mca suspension" },
    { 124, "PTRM ta suspension" },
    { 125, "Canceled: Investor Position Value Limit" },
    { 0,   NULL }
};

static const value_string ouch_quote_status_vals[] = {
    { 0, "Accept" },
    { 1, "Updated" },
    { 2, "Canceled" },
    { 3, "Unsolicited update" },
    { 4, "Unsolicited cancel" },
    { 5, "Traded" },
    { 0, NULL }
};

static int proto_bist_ouch;
static int ett_bist_ouch;
static int ett_bist_ouch_quote;

static int hf_ouch_msg_type;
static int hf_ouch_timestamp_ns;
static int hf_ouch_order_token;
static int hf_ouch_existing_order_token;
static int hf_ouch_prev_order_token;
static int hf_ouch_repl_order_token;
static int hf_ouch_orderbook_id;
static int hf_ouch_side;
static int hf_ouch_order_id;
static int hf_ouch_quantity;
static int hf_ouch_price_int;
static int hf_ouch_price_double;
static int hf_ouch_tif;
static int hf_ouch_openclose;
static int hf_ouch_client_account;
static int hf_ouch_customer_info;
static int hf_ouch_exchange_info;
static int hf_ouch_display_qty;
static int hf_ouch_client_category;
static int hf_ouch_offhours;
static int hf_ouch_smp_level;
static int hf_ouch_smp_method;
static int hf_ouch_smp_id;
static int hf_ouch_reject_code;
static int hf_ouch_order_state;
static int hf_ouch_pretrade_qty;
static int hf_ouch_reserved;
static int hf_ouch_no_quote_entries;
static int hf_ouch_q_entry_orderbook_id;
static int hf_ouch_q_entry_bid_px_int;
static int hf_ouch_q_entry_offer_px_int;
static int hf_ouch_q_entry_bid_sz;
static int hf_ouch_q_entry_offer_sz;
static int hf_ouch_quote_side;
static int hf_ouch_quote_status;
static int hf_ouch_cancel_reason;
static int hf_ouch_raw;
static int hf_ouch_match_id;
static int hf_ouch_traded_qty;

static int add_price(proto_tree *tree, int hf_int, int hf_double, tvbuff_t *tvb, int offset)
{
    int32_t raw = (int32_t)tvb_get_ntohl(tvb, offset);
    if (bist_ouch_show_decimal_price) {
        double val = ((double)raw) / 10000.0;
        proto_tree_add_double(tree, hf_double, tvb, offset, 4, val);
    } else {
        proto_tree_add_int(tree, hf_int, tvb, offset, 4, raw);
    }
    return offset + 4;
}

static int dissect_u_replace_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pt, int offset)
{
    /* Existing Order Token (EOT) — dedicated field */
    proto_item *eot_pi =
        proto_tree_add_item(pt, hf_ouch_existing_order_token, tvb, offset, 14, ENC_ASCII);
    proto_item *legacy_pi =
        proto_tree_add_item(pt, hf_ouch_order_token, tvb, offset, 14, ENC_ASCII);
    proto_item_set_generated(legacy_pi);

    (void)eot_pi;
    offset += 14;

    /* Replacement Order Token (ROT) */
    proto_tree_add_item(pt, hf_ouch_repl_order_token, tvb, offset, 14, ENC_ASCII); offset += 14;

    proto_tree_add_item(pt, hf_ouch_quantity, tvb, offset,  8, ENC_BIG_ENDIAN); offset += 8;
    offset = add_price(pt, hf_ouch_price_int, hf_ouch_price_double, tvb, offset);
    proto_tree_add_item(pt, hf_ouch_openclose, tvb, offset,  1, ENC_BIG_ENDIAN); offset += 1;
    proto_tree_add_item(pt, hf_ouch_client_account, tvb, offset, 16, ENC_ASCII); offset += 16;
    proto_tree_add_item(pt, hf_ouch_customer_info, tvb, offset, 15, ENC_ASCII);   offset += 15;
    proto_tree_add_item(pt, hf_ouch_exchange_info, tvb, offset, 32, ENC_ASCII);   offset += 32;
    proto_tree_add_item(pt, hf_ouch_display_qty, tvb, offset,  8, ENC_BIG_ENDIAN); offset += 8;
    proto_tree_add_item(pt, hf_ouch_client_category, tvb, offset,  1, ENC_BIG_ENDIAN); offset += 1;
    proto_tree_add_item(pt, hf_ouch_reserved, tvb, offset,  8, ENC_NA);           offset += 8;

    col_append_str(pinfo->cinfo, COL_INFO, ", Replace Order");
    return offset;
}

static int dissect_u_order_replaced(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pt, int offset)
{
    proto_tree_add_item(pt, hf_ouch_timestamp_ns, tvb, offset,  8, ENC_BIG_ENDIAN); offset += 8;
    proto_tree_add_item(pt, hf_ouch_repl_order_token, tvb, offset, 14, ENC_ASCII);  offset += 14;
    proto_tree_add_item(pt, hf_ouch_prev_order_token, tvb, offset, 14, ENC_ASCII);  offset += 14;
    proto_tree_add_item(pt, hf_ouch_orderbook_id, tvb, offset,  4, ENC_BIG_ENDIAN); offset += 4;
    proto_tree_add_item(pt, hf_ouch_side, tvb, offset,  1, ENC_BIG_ENDIAN);         offset += 1;
    proto_tree_add_item(pt, hf_ouch_order_id, tvb, offset,  8, ENC_BIG_ENDIAN);     offset += 8;
    proto_tree_add_item(pt, hf_ouch_quantity, tvb, offset,  8, ENC_BIG_ENDIAN);     offset += 8;
    offset = add_price(pt, hf_ouch_price_int, hf_ouch_price_double, tvb, offset);
    proto_tree_add_item(pt, hf_ouch_tif, tvb, offset,  1, ENC_BIG_ENDIAN);          offset += 1;
    proto_tree_add_item(pt, hf_ouch_openclose, tvb, offset,  1, ENC_BIG_ENDIAN);    offset += 1;
    proto_tree_add_item(pt, hf_ouch_client_account, tvb, offset, 16, ENC_ASCII);    offset += 16;
    proto_tree_add_item(pt, hf_ouch_order_state, tvb, offset,  1, ENC_BIG_ENDIAN);  offset += 1;
    proto_tree_add_item(pt, hf_ouch_customer_info, tvb, offset, 15, ENC_ASCII);     offset += 15;
    proto_tree_add_item(pt, hf_ouch_exchange_info, tvb, offset, 32, ENC_ASCII);     offset += 32;
    proto_tree_add_item(pt, hf_ouch_pretrade_qty, tvb, offset,  8, ENC_BIG_ENDIAN); offset += 8;
    proto_tree_add_item(pt, hf_ouch_display_qty, tvb, offset,  8, ENC_BIG_ENDIAN);  offset += 8;
    proto_tree_add_item(pt, hf_ouch_client_category, tvb, offset,  1, ENC_BIG_ENDIAN); offset += 1;
    col_append_str(pinfo->cinfo, COL_INFO, ", Order Replaced");
    return offset;
}

static bool ob_is_u_outbound(tvbuff_t *tvb)
{
    const int mlen = tvb_reported_length(tvb);
    if (mlen >= 145) return true;          /* Order Replaced (outbound) */
    if (mlen == 122) return false;         /* Replace Order (inbound)   */
    if (tvb_captured_length_remaining(tvb, 1) >= 8) {
        uint64_t ts = tvb_get_ntoh64(tvb, 1);
        if (ts > 1000000000000000000ULL)   /* timestamp heuristic */
            return true;
    }
    return false;                          /* fallback = inbound */
}

static int dissect_bist_ouch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    uint32_t type;
    const char* str_type;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, PSHORT);

    proto_item* ti = proto_tree_add_item(tree, proto_bist_ouch, tvb, 0, -1, ENC_NA);
    proto_tree *pt = proto_item_add_subtree(ti, ett_bist_ouch);

    proto_tree_add_item_ret_uint(pt, hf_ouch_msg_type, tvb, 0, 1, ENC_NA, &type);
    str_type = val_to_str_const(type, ouch_msg_types, "Unknown (0x%02x)");
    proto_item_append_text(ti, ", %s", str_type);
    col_set_str(pinfo->cinfo, COL_INFO, str_type);
    offset = 1;

    ob_token_info_t obti;
    ob_extract_token_info(tvb, pinfo, &obti);

    switch (type) {
    case 'O': { /* Enter Order */
        uint64_t qty = 0;

        proto_tree_add_item(pt, hf_ouch_order_token, tvb, offset, 14, ENC_ASCII); offset += 14;
        proto_tree_add_item(pt, hf_ouch_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        proto_tree_add_item(pt, hf_ouch_side, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;

        proto_tree_add_item_ret_uint64(pt, hf_ouch_quantity, tvb, offset, 8, ENC_BIG_ENDIAN, &qty);
        offset += 8;
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Qty=%" PRIu64, (uint64_t)qty);

        offset = add_price(pt, hf_ouch_price_int, hf_ouch_price_double, tvb, offset);
        proto_tree_add_item(pt, hf_ouch_tif, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_openclose, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_client_account, tvb, offset, 16, ENC_ASCII); offset += 16;
        proto_tree_add_item(pt, hf_ouch_customer_info, tvb, offset, 15, ENC_ASCII); offset += 15;
        proto_tree_add_item(pt, hf_ouch_exchange_info, tvb, offset, 32, ENC_ASCII); offset += 32;
        proto_tree_add_item(pt, hf_ouch_display_qty, tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
        proto_tree_add_item(pt, hf_ouch_client_category, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_offhours, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_smp_level, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_smp_method, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_smp_id, tvb, offset, 3, ENC_ASCII); offset += 3;
        if (tvb_captured_length_remaining(tvb, offset) >= 2) {
            proto_tree_add_item(pt, hf_ouch_reserved, tvb, offset, 2, ENC_NA); offset += 2;
        }
        break;
    }
    case 'U': { /* Replace Order vs Order Replaced */
        const int mlen = tvb_reported_length(tvb);
        if (mlen >= 145) {
            offset = dissect_u_order_replaced(tvb, pinfo, pt, offset);
        } else if (mlen == 122) {
            offset = dissect_u_replace_order(tvb, pinfo, pt, offset);
        } else {
            if (tvb_captured_length_remaining(tvb, 1) >= 8) {
                uint64_t ts = tvb_get_ntoh64(tvb, 1);
                if (ts > 1000000000000000000ULL) {
                    offset = dissect_u_order_replaced(tvb, pinfo, pt, offset);
                    break;
                }
            }
            offset = dissect_u_replace_order(tvb, pinfo, pt, offset);
        }
        break;
    }
    case 'X': { /* Cancel Order */
        proto_tree_add_item(pt, hf_ouch_order_token, tvb, offset, 14, ENC_ASCII); offset += 14;
        break;
    }
    case 'Y': { /* Cancel by Order ID */
        proto_tree_add_item(pt, hf_ouch_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        proto_tree_add_item(pt, hf_ouch_side, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_order_id, tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
        break;
    }
    case 'Q': { /* Mass Quote */
        proto_tree_add_item(pt, hf_ouch_order_token, tvb, offset, 14, ENC_ASCII); offset += 14;
        proto_tree_add_item(pt, hf_ouch_client_category, tvb, offset,  1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_client_account, tvb, offset, 16, ENC_ASCII); offset += 16;
        proto_tree_add_item(pt, hf_ouch_exchange_info, tvb, offset, 16, ENC_ASCII); offset += 16;
        if (tvb_captured_length_remaining(tvb, offset) < 2) break;
        uint16_t num_entries = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(pt, hf_ouch_no_quote_entries, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Entries=%u", num_entries);
        for (unsigned i = 0; i < num_entries && tvb_captured_length_remaining(tvb, offset) >= 28; i++) {
            proto_item *entry_item = proto_tree_add_item(pt, hf_ouch_raw, tvb, offset, 28, ENC_NA);
            proto_item_set_text(entry_item, "Quote Entry %u", i+1);
            proto_tree *entry_tree = proto_item_add_subtree(entry_item, ett_bist_ouch_quote);
            proto_tree_add_item(entry_tree, hf_ouch_q_entry_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
            offset = add_price(entry_tree, hf_ouch_q_entry_bid_px_int, hf_ouch_price_double, tvb, offset);
            offset = add_price(entry_tree, hf_ouch_q_entry_offer_px_int, hf_ouch_price_double, tvb, offset);
            proto_tree_add_item(entry_tree, hf_ouch_q_entry_bid_sz, tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
            proto_tree_add_item(entry_tree, hf_ouch_q_entry_offer_sz, tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
        }
        break;
    }
    case 'A': { /* Order Accepted */
        proto_tree_add_item(pt, hf_ouch_timestamp_ns, tvb, offset,  8, ENC_BIG_ENDIAN); offset += 8;
        proto_tree_add_item(pt, hf_ouch_order_token, tvb, offset, 14, ENC_ASCII); offset += 14;
        proto_tree_add_item(pt, hf_ouch_orderbook_id, tvb, offset,  4, ENC_BIG_ENDIAN); offset += 4;
        proto_tree_add_item(pt, hf_ouch_side, tvb, offset,  1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_order_id, tvb, offset,  8, ENC_BIG_ENDIAN); offset += 8;
        proto_tree_add_item(pt, hf_ouch_quantity, tvb, offset,  8, ENC_BIG_ENDIAN); offset += 8;
        offset = add_price(pt, hf_ouch_price_int, hf_ouch_price_double, tvb, offset);
        proto_tree_add_item(pt, hf_ouch_tif, tvb, offset,  1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_openclose, tvb, offset,  1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_client_account,tvb, offset, 16, ENC_ASCII); offset += 16;
        proto_tree_add_item(pt, hf_ouch_order_state, tvb, offset,  1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_customer_info, tvb, offset, 15, ENC_ASCII); offset += 15;
        proto_tree_add_item(pt, hf_ouch_exchange_info, tvb, offset, 32, ENC_ASCII); offset += 32;
        proto_tree_add_item(pt, hf_ouch_pretrade_qty, tvb, offset,  8, ENC_BIG_ENDIAN); offset += 8;
        proto_tree_add_item(pt, hf_ouch_display_qty, tvb, offset,  8, ENC_BIG_ENDIAN); offset += 8;
        proto_tree_add_item(pt, hf_ouch_client_category, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_offhours, tvb, offset,  1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_smp_level, tvb, offset,  1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_smp_method, tvb, offset,  1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_smp_id, tvb, offset,  3, ENC_ASCII); offset += 3;
        break;
    }
    case 'J': { /* Order Rejected */
        proto_tree_add_item(pt, hf_ouch_timestamp_ns, tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
        proto_tree_add_item(pt, hf_ouch_order_token, tvb, offset,14, ENC_ASCII); offset += 14;
        proto_tree_add_item(pt, hf_ouch_reject_code, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        break;
    }
    case 'C': { /* Order Canceled */
        proto_tree_add_item(pt, hf_ouch_timestamp_ns, tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
        proto_tree_add_item(pt, hf_ouch_order_token, tvb, offset,14, ENC_ASCII); offset += 14;
        proto_tree_add_item(pt, hf_ouch_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        proto_tree_add_item(pt, hf_ouch_side, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_order_id, tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
        proto_tree_add_item(pt, hf_ouch_cancel_reason, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        break;
    }
    case 'E': { /* Order Executed */
        uint64_t traded_qty = 0;

        proto_tree_add_item(pt, hf_ouch_timestamp_ns, tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
        proto_tree_add_item(pt, hf_ouch_order_token, tvb, offset, 14, ENC_ASCII); offset += 14;
        proto_tree_add_item(pt, hf_ouch_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;

        proto_tree_add_item_ret_uint64(pt, hf_ouch_quantity, tvb, offset, 8, ENC_BIG_ENDIAN, &traded_qty);
        offset += 8;
        col_append_fstr(pinfo->cinfo, COL_INFO, ", TradedQty=%" PRIu64, (uint64_t)traded_qty);
        offset = add_price(pt, hf_ouch_price_int, hf_ouch_price_double, tvb, offset);
        proto_tree_add_item(pt, hf_ouch_match_id, tvb, offset, 12, ENC_NA); offset += 12;
        proto_tree_add_item(pt, hf_ouch_client_category, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_reserved, tvb, offset, 16, ENC_NA); offset += 16;
        break;
    }
    case 'K': { /* Mass Quote Ack */
        uint64_t qty = 0, traded_qty = 0;
        proto_tree_add_item(pt, hf_ouch_timestamp_ns, tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
        proto_tree_add_item(pt, hf_ouch_order_token, tvb, offset, 14, ENC_ASCII); offset += 14;
        proto_tree_add_item(pt, hf_ouch_q_entry_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        proto_tree_add_item_ret_uint64(pt, hf_ouch_quantity, tvb, offset, 8, ENC_BIG_ENDIAN, &qty); offset += 8;
        proto_tree_add_item_ret_uint64(pt, hf_ouch_traded_qty, tvb, offset, 8, ENC_BIG_ENDIAN, &traded_qty); offset += 8;
        offset = add_price(pt, hf_ouch_price_int, hf_ouch_price_double, tvb, offset);
        proto_tree_add_item(pt, hf_ouch_side, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
        proto_tree_add_item(pt, hf_ouch_quote_status, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Qty=%" PRIu64 ", Traded=%" PRIu64, (uint64_t)qty, (uint64_t)traded_qty);
        break;
    }
    case 'R': { /* Mass Quote Rejection */
        proto_tree_add_item(pt, hf_ouch_timestamp_ns, tvb, offset, 8, ENC_BIG_ENDIAN); offset += 8;
        proto_tree_add_item(pt, hf_ouch_order_token,  tvb, offset,14, ENC_ASCII); offset += 14;
        if (tvb_captured_length_remaining(tvb, offset) >= 4) {
            proto_tree_add_item(pt, hf_ouch_q_entry_orderbook_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        }
        if (tvb_captured_length_remaining(tvb, offset) >= 4) {
            proto_tree_add_item(pt, hf_ouch_reject_code, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
        }
        if (tvb_captured_length_remaining(tvb, offset) > 0) {
            int rem2 = tvb_captured_length_remaining(tvb, offset);
            proto_tree_add_item(pt, hf_ouch_raw, tvb, offset, rem2, ENC_NA); offset += rem2;
        }
        break;
    }
    default: {
        int rem = tvb_captured_length_remaining(tvb, offset);
        if (rem > 0) proto_tree_add_item(pt, hf_ouch_raw, tvb, offset, rem, ENC_NA);
        break;
    }
    }

    int rem = tvb_captured_length_remaining(tvb, offset);
    if (rem > 0) proto_tree_add_item(pt, hf_ouch_raw, tvb, offset, rem, ENC_NA);
    if (bist_ouch_enable_orderbook_tracking) {
        ob_track_and_annotate(tvb, pinfo, pt, ti);
    }

    return tvb_captured_length(tvb);
}

static bool dissect_bist_ouch_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if (tvb_captured_length(tvb) < 1)
        return false;

    uint8_t msg_type = tvb_get_uint8(tvb, 0);
    int idx = -1;
    const char *s = try_val_to_str_idx(msg_type, ouch_msg_types, &idx);
    if (s != NULL) {
        dissect_bist_ouch(tvb, pinfo, tree, NULL);
        return true;
    }
    return false;
}

void proto_register_bist_ouch(void)
{
    static hf_register_info hf[] = {
        { &hf_ouch_msg_type,        { "Message Type", "bist_ouch.msg_type", FT_UINT8, BASE_HEX, VALS(ouch_msg_types), 0x0, NULL, HFILL }},
        { &hf_ouch_timestamp_ns,    { "Timestamp (ns)", "bist_ouch.timestamp_ns", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_order_token,     { "Order Token", "bist_ouch.order_token", FT_STRING, BASE_NONE, NULL, 0x0, "Order/Quote token (generic — may be generated)", HFILL }},
        { &hf_ouch_existing_order_token,{ "Existing Order Token", "bist_ouch.existing_order_token", FT_STRING, BASE_NONE, NULL, 0x0, "Token that references the order to be replaced (should be the original Enter Order token)", HFILL }}, /* NEW */
        { &hf_ouch_prev_order_token,{ "Previous Order Token", "bist_ouch.prev_order_token", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_repl_order_token,{ "Replacement Order Token", "bist_ouch.repl_order_token", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_orderbook_id,    { "Order Book ID", "bist_ouch.orderbook_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_side,            { "Side", "bist_ouch.side", FT_UINT8, BASE_HEX, VALS(ouch_side_vals), 0x0, NULL, HFILL }},
        { &hf_ouch_order_id,        { "Order ID", "bist_ouch.order_id", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_quantity,        { "Quantity", "bist_ouch.quantity", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_price_int,       { "Price (int)", "bist_ouch.price.int", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_price_double,    { "Price", "bist_ouch.price", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_tif,             { "Time In Force", "bist_ouch.tif", FT_UINT8, BASE_DEC, VALS(ouch_tif_vals), 0x0, NULL, HFILL }},
        { &hf_ouch_openclose,       { "Open/Close", "bist_ouch.openclose", FT_UINT8, BASE_DEC, VALS(ouch_openclose_vals), 0x0, NULL, HFILL }},
        { &hf_ouch_client_account,  { "Client/Account", "bist_ouch.client_account", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_customer_info,   { "Customer Info", "bist_ouch.customer_info", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_exchange_info,   { "Exchange Info", "bist_ouch.exchange_info", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_display_qty,     { "Display Quantity", "bist_ouch.display_qty", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_client_category, { "Client Category", "bist_ouch.client_category", FT_UINT8, BASE_DEC, VALS(ouch_client_cat_vals), 0x0, NULL, HFILL }},
        { &hf_ouch_offhours,        { "OffHours", "bist_ouch.offhours", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_smp_level,       { "SMP Level", "bist_ouch.smp_level", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_smp_method,      { "SMP Method", "bist_ouch.smp_method", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_smp_id,          { "SMP ID", "bist_ouch.smp_id", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_reject_code,     { "Reject Code", "bist_ouch.reject_code", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_order_state,     { "Order State", "bist_ouch.order_state", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_pretrade_qty,    { "Pre-Trade Qty", "bist_ouch.qty2", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_no_quote_entries,{ "NoQuoteEntries", "bist_ouch.mq.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_q_entry_orderbook_id, { "Quote OrderBookID", "bist_ouch.mq.ob", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_q_entry_bid_px_int,   { "Bid Px (int)", "bist_ouch.mq.bid_px.int", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_q_entry_offer_px_int, { "Offer Px (int)", "bist_ouch.mq.offer_px.int", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_q_entry_bid_sz,       { "Bid Size", "bist_ouch.mq.bid_sz", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_q_entry_offer_sz,     { "Offer Size", "bist_ouch.mq.offer_sz", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_quote_side,           { "Quote Side", "bist_ouch.mq.side", FT_UINT8, BASE_HEX, VALS(ouch_side_vals), 0x0, NULL, HFILL }},
        { &hf_ouch_quote_status,         { "Quote Status", "bist_ouch.mq.status", FT_UINT32, BASE_DEC, VALS(ouch_quote_status_vals), 0x0, NULL, HFILL }},
        { &hf_ouch_cancel_reason,        { "Cancel Reason", "bist_ouch.cancel_reason", FT_UINT8, BASE_DEC, VALS(ouch_cancel_reason_vals), 0x0, NULL, HFILL }},
        { &hf_ouch_raw,                  { "Raw", "bist_ouch.raw", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_reserved,             { "Reserved", "bist_ouch.reserved", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_match_id,             { "Match ID", "bist_ouch.match_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ouch_traded_qty,           { "Traded Quantity", "bist_ouch.traded_qty", FT_UINT64, BASE_DEC, NULL, 0x0, "Total traded quantity for this order", HFILL }},
        { &hf_ob_initial_token,     { "Orderbook • Initial Token",      "bist_ouch.order.initial_token",     FT_STRING, BASE_NONE, NULL, 0x0, "Initial inbound Order Token (IOT)", HFILL }},
        { &hf_ob_replacement_token, { "Orderbook • Replacement Token",  "bist_ouch.order.replacement_token", FT_STRING, BASE_NONE, NULL, 0x0, "Replacement Order Token on this frame (if any)", HFILL }},
        { &hf_ob_previous_token,    { "Orderbook • Previous Token",     "bist_ouch.order.previous_token",    FT_STRING, BASE_NONE, NULL, 0x0, "Previous Replacement Token (links ROT chain)", HFILL }},
        { &hf_ob_group_index,       { "Orderbook • Order Index",        "bist_ouch.order.group_index",       FT_UINT32, BASE_DEC,  NULL, 0x0, "Flare-style event index within this order lifecycle", HFILL }},
        { &hf_ob_group_size,        { "Orderbook • OrderChain Size",    "bist_ouch.order.group_size",        FT_UINT32, BASE_DEC,  NULL, 0x0, "Progressive count of events seen for this order", HFILL }},
        { &hf_ob_is_inbound,        { "Orderbook • Is Inbound",         "bist_ouch.order.is_inbound",        FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Message direction (client→exchange)", HFILL }},
        { &hf_ob_global_index,      { "Orderbook • Global Index",       "bist_ouch.order.global_index",      FT_UINT32, BASE_DEC,  NULL, 0x0, "Capture-wide absolute OUCH message index (unique)", HFILL }},
        { &hf_ob_group_id,          { "Orderbook • OrderChain ID",      "bist_ouch.order.group_id",          FT_UINT32, BASE_DEC,  NULL, 0x0, "Capture-wide ordinal ID of the order group", HFILL }},
    };

    static int *ett[] = { &ett_bist_ouch, &ett_bist_ouch_quote, &ett_bist_ouch_orderbook };

    static ei_register_info ei[] = {
        { &ei_ob_prev_unmapped,   { "bist_ouch.order.prev_unmapped",   PI_PROTOCOL, PI_WARN, "Previous token was not mapped in this session (partial capture?)", EXPFILL } },
        { &ei_ob_eot_not_initial, { "bist_ouch.order.eot_not_initial", PI_PROTOCOL, PI_NOTE, "Existing Order Token differs from the initial Enter Order token (allowed now, may not be supported later)", EXPFILL } } /* NEW */
    };

    proto_bist_ouch = proto_register_protocol(PNAME, PSHORT, PFILT);
    proto_register_field_array(proto_bist_ouch, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module_t* expert_bist_ouch = expert_register_protocol(proto_bist_ouch);
    expert_register_field_array(expert_bist_ouch, ei, array_length(ei));

    /* Prefs */
    module_t *pref = prefs_register_protocol(proto_bist_ouch, NULL);
    prefs_register_bool_preference(pref, "show_decimal_price",
        "Show Prices as Decimals (/10000)",
        "If enabled, 4-byte signed price fields are divided by 10000 and shown as doubles.",
        &bist_ouch_show_decimal_price);

    prefs_register_bool_preference(pref, "enable_orderbook_tracking",
        "Enable Orderbook Tracking",
        "If enabled, maintains capture-lifetime order groups and event indices across streams.",
        &bist_ouch_enable_orderbook_tracking);

    prefs_register_bool_preference(pref, "show_order_index_in_info",
        "Append OrderIndex#<index> (message-in-group) to Info",
        "If enabled, appends the per-order message index (OrderIndex#) in the Info column.",
        &bist_ouch_show_order_index_in_info);

    prefs_register_bool_preference(pref, "show_global_index_in_info",
        "Append GlobalIndex#<absolute_index> to Info",
        "If enabled, appends the capture-wide absolute OUCH index (Global#) after other counters.",
        &bist_ouch_show_global_index_in_info);

    prefs_register_bool_preference(pref, "show_group_id_in_info",
        "Append OrderChainID#<group_id> to Info",
        "If enabled, appends the capture-wide group ordinal (OrderChainID#) to the Info column.",
        &bist_ouch_show_group_id_in_info);

    prefs_register_bool_preference(pref, "show_match_in_info",
        "Append Match#<id> (token-based) to Info",
        "If enabled, appends Match#<id> based on replacement token for 'U' messages and Order Token for others.",
        &bist_ouch_show_match_in_info);

    bist_ouch_handle = register_dissector("bist-ouch", dissect_bist_ouch, proto_bist_ouch);

    register_init_routine(bist_ouch_reset_state);
}

void proto_reg_handoff_bist_ouch(void)
{
    heur_dissector_add("soupbintcp", dissect_bist_ouch_heur, "BIST OUCH over SoupBinTCP", "bist_ouch_soupbintcp", proto_bist_ouch, HEURISTIC_ENABLE);
}

static void bist_ouch_reset_state(void)
{
    g_current_file_scope = NULL;
    g_token_to_group = NULL;
    g_frame_to_index = NULL;
    g_next_global_index = 1;
    g_next_group_id    = 1;
    g_stream_session_tracking = NULL;
    g_frame_to_partner_global = NULL;
}

static void ob_lazy_reset_on_new_capture(packet_info *pinfo _U_)
{
    wmem_allocator_t *fs = wmem_file_scope();
    if (fs != g_current_file_scope) {
        g_current_file_scope = fs;
        g_token_to_group = NULL;
        g_frame_to_index = NULL;
        g_next_global_index = 1;
        g_next_group_id    = 1;
        g_stream_session_tracking = NULL;
        g_frame_to_partner_global = NULL;
    }
    if (!g_token_to_group)                g_token_to_group                = wmem_map_new(g_current_file_scope, ob_str_hash, ob_str_equal);
    if (!g_frame_to_index)                g_frame_to_index                = wmem_map_new(g_current_file_scope, g_direct_hash, g_direct_equal);
    if (!g_stream_session_tracking)       g_stream_session_tracking       = wmem_map_new(g_current_file_scope, ob_stream_key_hash, ob_stream_key_equal);
    if (!g_frame_to_partner_global)       g_frame_to_partner_global       = wmem_map_new(g_current_file_scope, g_direct_hash, g_direct_equal);
}

static order_group_t* ob_find_root(order_group_t *g)
{
    if (!g) return NULL;
    order_group_t *root = g;
    while (root->parent) {
        root = root->parent;
    }
    order_group_t *current = g;
    while (current != root) {
        order_group_t *next = current->parent;
        current->parent = root;
        current = next;
    }
    return root;
}

static order_group_t* ob_union_groups(order_group_t *a, order_group_t *b)
{
    if (!a) return ob_find_root(b);
    if (!b) return ob_find_root(a);
    a = ob_find_root(a);
    b = ob_find_root(b);
    if (a == b) return a;

    order_group_t *root = (a->first_frame <= b->first_frame) ? a : b;
    order_group_t *child= (root == a) ? b : a;

    child->parent = root;

    if (child->next_index > root->next_index) root->next_index = child->next_index;
    if (child->total      > root->total)      root->total      = child->total;

    if (!root->initial_token && child->initial_token)
        root->initial_token = child->initial_token;

    return root;
}

static order_group_t* ob_lookup_group(wmem_map_t *token_map, const char *token)
{
    if (!token || !token_map) return NULL;
    order_group_t *g = (order_group_t *)wmem_map_lookup(token_map, token);
    return ob_find_root(g);
}

static void ob_map_token_to_group(wmem_map_t *token_map, const char *token, order_group_t *g)
{
    if (!token || !g) return;
    if (wmem_map_lookup(token_map, token) == g) return;
    const char *tok_fs = wmem_strdup(wmem_file_scope(), token);
    wmem_map_insert(token_map, (void *)tok_fs, g);
}

static order_group_t* ob_ensure_group_for_token(wmem_map_t *token_map, const char *token, uint64_t frame_num)
{
    order_group_t *g = ob_lookup_group(token_map, token);
    if (!g) {
        g = wmem_new0(wmem_file_scope(), order_group_t);
        g->initial_token = NULL;
        g->first_frame   = frame_num;
        g->next_index    = 1;
        g->total         = 0;
        g->group_id      = g_next_group_id++;
        ob_map_token_to_group(token_map, token, g);
    }
    return g;
}

static const char* ob_get_ascii_token(tvbuff_t *tvb, int offset, int len, wmem_allocator_t *scope)
{
    if (offset < 0 || len <= 0) return NULL;
    if (tvb_captured_length_remaining(tvb, offset) < len) return NULL;
    return tvb_get_string_enc(scope, tvb, offset, len, ENC_ASCII);
}

static uint64_t ob_make_stream_token_key(packet_info *pinfo, const char *token)
{
    if (!token) return 0;

    conversation_t *conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                            CONVERSATION_TCP, pinfo->srcport, pinfo->destport, 0);
    if (!conv) {
        conv = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
                               CONVERSATION_TCP, pinfo->srcport, pinfo->destport, 0);
    }

    uint32_t stream_id = (uint32_t)(uintptr_t)conv;
    uint32_t token_hash = g_str_hash(token);

    return ((uint64_t)stream_id << 32) | (token_hash & 0xFFFFFFFF);
}

static stream_session_tracking_t* ob_get_stream_tracking(packet_info *pinfo, const char *token)
{
    if (!token) return NULL;

    uint64_t stream_key = ob_make_stream_token_key(pinfo, token);
    void *key_ptr = (void *)(uintptr_t)stream_key;

    stream_session_tracking_t *tracking = wmem_map_lookup(g_stream_session_tracking, key_ptr);
    if (!tracking) {
        tracking = wmem_new0(wmem_file_scope(), stream_session_tracking_t);
        wmem_map_insert(g_stream_session_tracking, key_ptr, tracking);
    }
    return tracking;
}



static void ob_extract_token_info(tvbuff_t *tvb, packet_info *pinfo, ob_token_info_t *ti)
{
    memset(ti, 0, sizeof(*ti));
    ti->type = tvb_get_uint8(tvb, 0);

    switch (ti->type) {
    case 'O': /* inbound */
        ti->is_inbound = true;
        ti->iot = ob_get_ascii_token(tvb, 1, 14, pinfo->pool);
        ti->has_iot = (ti->iot != NULL);
        break;
    case 'U': {
        const bool outbound = ob_is_u_outbound(tvb);
        ti->is_inbound = !outbound;

        if (outbound) {
            /* Outbound "Order Replaced": ts(8), ROT(14), PREV(14) */
            ti->rot  = ob_get_ascii_token(tvb, 1+8,     14, pinfo->pool);
            ti->prev = ob_get_ascii_token(tvb, 1+8+14,  14, pinfo->pool);
            ti->has_rot  = (ti->rot  != NULL);
            ti->has_prev = (ti->prev != NULL);
        } else {
            /* Inbound Replace Order: EOT then proposed ROT */
            ti->iot = ob_get_ascii_token(tvb, 1,     14, pinfo->pool);      /* EOT */
            ti->rot = ob_get_ascii_token(tvb, 1+14,  14, pinfo->pool);      /* proposed ROT */
            ti->has_iot = (ti->iot != NULL);
            ti->has_rot = (ti->rot != NULL);
        }
        break;
    }
    case 'X': /* inbound cancel */
        ti->is_inbound = true;
        ti->iot = ob_get_ascii_token(tvb, 1, 14, pinfo->pool);
        ti->has_iot = (ti->iot != NULL);
        break;
    case 'Y': /* inbound by Order ID – no token */
        ti->is_inbound = true;
        break;
    case 'Q': /* inbound mass quote */
        ti->is_inbound = true;
        ti->iot = ob_get_ascii_token(tvb, 1, 14, pinfo->pool);
        ti->has_iot = (ti->iot != NULL);
        break;
    case 'A': /* outbound accept */
    case 'J': /* outbound reject */
    case 'C': /* outbound cancel */
    case 'E': /* outbound exec */
    case 'K': /* outbound mq ack */
    case 'R': /* outbound mq rej */
        ti->is_inbound = false;
        ti->iot = ob_get_ascii_token(tvb, 1+8, 14, pinfo->pool); /* ts(8) then token */
        ti->has_iot = (ti->iot != NULL);
        break;
    default:
        break;
    }
}
static void ob_track_and_annotate(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pt, proto_item *root_item)
{
    ob_lazy_reset_on_new_capture(pinfo);

    ob_token_info_t ti;
    ob_extract_token_info(tvb, pinfo, &ti);

    wmem_map_t *token_map = g_token_to_group;

    order_group_t *group = NULL;

    if (ti.type == 'U' && !ti.is_inbound) {
        /* Outbound Order Replaced: bind PREV -> group, map ROT into same group */
        if (ti.has_prev) {
            group = ob_lookup_group(token_map, ti.prev);
            if (!group) {
                group = ob_ensure_group_for_token(token_map, ti.prev, pinfo->fd->num);
                if (root_item) {
                    expert_add_info_format(pinfo, root_item, &ei_ob_prev_unmapped,
                        "Order Replaced: previous token '%s' was not mapped in this session; created a temporary group (partial capture?)", ti.prev);
                }
            }
            if (ti.has_rot) {
                ob_map_token_to_group(token_map, ti.rot, group);
            }
        } else if (ti.has_rot) {
            group = ob_lookup_group(token_map, ti.rot);
            if (!group) group = ob_ensure_group_for_token(token_map, ti.rot, pinfo->fd->num);
        }
    } else if (ti.type == 'U' && ti.is_inbound) {
        /* Inbound Replace Order: unify EOT and ROT */
        order_group_t *g_iot = ti.has_iot ? ob_lookup_group(token_map, ti.iot) : NULL;
        order_group_t *g_rot = ti.has_rot ? ob_lookup_group(token_map, ti.rot) : NULL;

        if (!g_iot && !g_rot) {
            g_iot = ob_ensure_group_for_token(token_map, ti.iot, pinfo->fd->num);
            if (!g_iot->initial_token) g_iot->initial_token = wmem_strdup(wmem_file_scope(), ti.iot);
            group = g_iot;
        } else if (g_rot && !g_iot) {
            if (!g_rot->initial_token)
                g_rot->initial_token = wmem_strdup(wmem_file_scope(), ti.iot);
            ob_map_token_to_group(token_map, ti.iot, g_rot);
            group = g_rot;
        } else if (g_iot && g_rot && g_iot != g_rot) {
            order_group_t *root = ob_union_groups(g_iot, g_rot);
            if (!root->initial_token) root->initial_token = wmem_strdup(wmem_file_scope(), ti.iot);
            ob_map_token_to_group(token_map, ti.iot, root);
            if (ti.has_rot) ob_map_token_to_group(token_map, ti.rot, root);
            group = root;
        } else {
            group = g_iot ? g_iot : g_rot;
            if (group && !group->initial_token && ti.has_iot)
                group->initial_token = wmem_strdup(wmem_file_scope(), ti.iot);
            if (group && ti.has_iot) ob_map_token_to_group(token_map, ti.iot, group);
        }

        /* soft note when EOT != initial token (allowed now, may not later) */
        if (ti.has_iot && group && group->initial_token && strcmp(ti.iot, group->initial_token) != 0 && root_item) {
            expert_add_info(pinfo, root_item, &ei_ob_eot_not_initial);
        }

    } else {
        /* Other messages carrying an order token */
        if (ti.has_iot) {
            group = ob_lookup_group(token_map, ti.iot);
            if (!group) {
                /* For outbound reject ('J'), try inherit from last inbound frame carrying same token */
                if (ti.type == 'J') {
                    stream_session_tracking_t *tracking = ob_get_stream_tracking(pinfo, ti.iot);
                    if (tracking && tracking->last_inbound_frame > 0) {
                        ob_frame_idx_t *prev_pd = (ob_frame_idx_t *)wmem_map_lookup(g_frame_to_index, GUINT_TO_POINTER(tracking->last_inbound_frame));
                        if (prev_pd && prev_pd->group) {
                            group = ob_find_root(prev_pd->group);
                            ob_map_token_to_group(token_map, ti.iot, group);
                        }
                    }
                }
                if (!group) {
                    group = ob_ensure_group_for_token(token_map, ti.iot, pinfo->fd->num);
                }
            }
            if (!group->initial_token)
                group->initial_token = wmem_strdup(wmem_file_scope(), ti.iot);
            ob_map_token_to_group(token_map, ti.iot, group);
        }
    }
    void *fkey = GUINT_TO_POINTER((guint)pinfo->fd->num);
    ob_frame_idx_t *pd = (ob_frame_idx_t *)wmem_map_lookup(g_frame_to_index, fkey);
    if (!pd) {
        pd = wmem_new0(wmem_file_scope(), ob_frame_idx_t);
        if (!pinfo->fd->visited) {
            pd->global_index = g_next_global_index++;
        }
        wmem_map_insert(g_frame_to_index, fkey, pd);
    }

    if (group) {
        if (!pd->index) {
            if (!pinfo->fd->visited) {
                order_group_t *root = ob_find_root(group);
                pd->index = root->next_index++;
                root->total = root->next_index - 1;
                pd->group = root;
            } else {
                pd->index = 0;
                pd->group = ob_find_root(group);
            }
        }
    }

    const uint32_t idx  = pd->index;
    const uint32_t gidx = pd->global_index;
    const uint32_t gid  = (pd->group ? pd->group->group_id : 0);

    if (bist_ouch_show_group_id_in_info && gid > 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " OrderChainID#%u", gid);
    }
    if (bist_ouch_show_order_index_in_info && idx > 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " OrderIndex#%u", idx);
    }
    if (bist_ouch_show_global_index_in_info && gidx > 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " GlobalIndex#%u", gidx);
    }

    if (bist_ouch_show_match_in_info) {
        const char *match_token = NULL;
        if (ti.type == 'U') {
            if (ti.has_rot) match_token = ti.rot; /* ROT for Replace flow */
        } else {
            if (ti.has_iot) match_token = ti.iot; /* otherwise token carried */
        }
        if (match_token) {
            void *fmatch = wmem_map_lookup(g_frame_to_partner_global, GUINT_TO_POINTER((guint)pinfo->fd->num));
            if (fmatch) {
                col_append_fstr(pinfo->cinfo, COL_INFO, " Match#%u", GPOINTER_TO_UINT(fmatch));
            } else {
                const bool is_inbound = ti.is_inbound ? TRUE : FALSE;
                uint32_t partner_global = 0;

                // Use stream-based tracking
                stream_session_tracking_t *tracking = ob_get_stream_tracking(pinfo, match_token);
                if (tracking) {
                    if (is_inbound) {
                        partner_global = tracking->last_outbound_global;
                    } else {
                        partner_global = tracking->last_inbound_global;
                    }

                    if (partner_global > 0) {
                        col_append_fstr(pinfo->cinfo, COL_INFO, " Match#%u", partner_global);
                        uint32_t prev_frame = is_inbound ? tracking->last_outbound_frame : tracking->last_inbound_frame;
                        if (prev_frame > 0) {
                            wmem_map_insert(g_frame_to_partner_global, GUINT_TO_POINTER(prev_frame), GUINT_TO_POINTER(gidx));
                        }
                    }

                    // Update tracking
                    if (is_inbound) {
                        tracking->last_inbound_global = gidx;
                        tracking->last_inbound_frame = (uint32_t)pinfo->fd->num;
                    } else {
                        tracking->last_outbound_global = gidx;
                        tracking->last_outbound_frame = (uint32_t)pinfo->fd->num;
                    }
                }
            }
        }
    }

    proto_item *ob_item = NULL;
    proto_tree *ob_tree = proto_tree_add_subtree_format(pt, tvb, 0, 0,
                                ett_bist_ouch_orderbook, &ob_item, "Orderbook");

    const char *canon_iot = NULL;
    if (group) canon_iot = ob_find_root(group)->initial_token;
    if (!canon_iot && ti.has_iot) canon_iot = ti.iot; /* if this frame carries IOT, show it */

    if (canon_iot) {
        proto_tree_add_string(ob_tree, hf_ob_initial_token, tvb, 0, 0, canon_iot);
    }
    if (ti.has_rot) {
        proto_tree_add_string(ob_tree, hf_ob_replacement_token, tvb, 0, 0, ti.rot);
    }
    if (ti.has_prev && ob_is_u_outbound(tvb)) {
        /* Only meaningful for outbound Order Replaced */
        proto_tree_add_string(ob_tree, hf_ob_previous_token, tvb, 0, 0, ti.prev);
    }

    proto_tree_add_boolean(ob_tree, hf_ob_is_inbound, tvb, 0, 0, ti.is_inbound ? 1 : 0);
    if (gid  > 0) proto_tree_add_uint(ob_tree, hf_ob_group_id,     tvb, 0, 0, gid);
    if (idx  > 0) proto_tree_add_uint(ob_tree, hf_ob_group_index,  tvb, 0, 0, idx);
    if (gidx > 0) proto_tree_add_uint(ob_tree, hf_ob_global_index, tvb, 0, 0, gidx);

    if (group) {
        uint32_t display_total = ob_find_root(group)->total;
        if (display_total == 0 && idx > 0) display_total = idx;
        proto_tree_add_uint(ob_tree, hf_ob_group_size, tvb, 0, 0, display_total);
    }
}
