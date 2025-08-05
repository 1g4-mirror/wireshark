/* packet-bist-itch.c
 * Routines for BIST-ITCH dissection
 * Copyright 2025, Sadettin Er <sadettin.er@b-ulltech.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
//
//  Documentation:
//  https://www.borsaistanbul.com/files/bistech-itch-protocol-specification.pdf

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <wsutil/type_util.h>
#include <wsutil/wmem/wmem.h>

static bool bist_show_bigint_price = false;
static dissector_handle_t bist_handle;

static const value_string message_types_val[] = {
    { 'A', "Add Order"                 },
    { 'Z', "Equilibrium Price"         },
    { 'M', "Combo Leg"                 },
    { 'E', "Order Executed"            },
    { 'T', "Second"                    },
    { 'P', "Trade"                     },
    { 'C', "Order Executed w/ Price"   },
    { 'D', "Order Delete"              },
    { 'S', "System Event"              },
    { 'R', "Order Book Directory"      },
    { 'Y', "Order Book Flush"          },
    { 'V', "Short Sell Status"         },
    { 'O', "Order Book State"          },
    { 'L', "Tick Size"                 },
    { 0,     NULL                       }
};

static const value_string bist_itch_side_vals[] = {
    { 'B', "Buy"  },
    { 'S', "Sell" },
    { 0,    NULL   }
};

static const value_string bist_itch_event_vals[] = {
    { 'O', "Start of Messages" },
    { 'C', "End of Messages"   },
    { 0,    NULL               }
};


#define DECLARE_HF(x) static int hf_bist_##x
DECLARE_HF(message);                DECLARE_HF(version);
DECLARE_HF(message_type);           DECLARE_HF(nanosecond);
DECLARE_HF(second);                 DECLARE_HF(orderbook_id);
DECLARE_HF(order_id);               DECLARE_HF(side);
DECLARE_HF(quantity);               DECLARE_HF(price);
DECLARE_HF(match_id);               DECLARE_HF(combo_group);
DECLARE_HF(printable);              DECLARE_HF(occured_cross);
DECLARE_HF(event_code);             DECLARE_HF(symbol);
DECLARE_HF(isin);                   DECLARE_HF(financial_product);
DECLARE_HF(trading_currency);       DECLARE_HF(tick_size);
DECLARE_HF(price_from);             DECLARE_HF(price_to);
DECLARE_HF(leg_order_book);         DECLARE_HF(leg_side);
DECLARE_HF(leg_ratio);              DECLARE_HF(short_sell_status);
DECLARE_HF(state_name);             DECLARE_HF(bid_qty);
DECLARE_HF(ask_qty);                DECLARE_HF(best_bid_price);
DECLARE_HF(best_ask_price);         DECLARE_HF(best_bid_qty);
DECLARE_HF(ranking_seq);            DECLARE_HF(ranking_time);
DECLARE_HF(order_attributes);       DECLARE_HF(lot_type);
DECLARE_HF(long_name);              DECLARE_HF(price_decimals);
DECLARE_HF(nominal_decimals);       DECLARE_HF(odd_lot_size);
DECLARE_HF(round_lot_size);         DECLARE_HF(block_lot_size);
DECLARE_HF(nominal_value);          DECLARE_HF(number_of_leg);
DECLARE_HF(underlying_orderbook_id);DECLARE_HF(strike_price);
DECLARE_HF(expiration_date);        DECLARE_HF(strike_price_decimals);
DECLARE_HF(put_or_call);            DECLARE_HF(ranking_type);
DECLARE_HF(combo_orderbook_id);
#undef DECLARE_HF

static int  proto_bist;
static int ett_bist_itch;


static int add_uint(proto_tree *tree, int hf_id, tvbuff_t *tvb, int offset, int len)
{
    uint64_t v = tvb_get_bits64(tvb, offset*8, len*8, ENC_BIG_ENDIAN);
    if (len == 8)
        proto_tree_add_uint64(tree, hf_id, tvb, offset, len, v);
    else
        proto_tree_add_uint  (tree, hf_id, tvb, offset, len, (uint32_t)v);
    return offset + len;
}

static int add_string(proto_tree *tree, int hf_id, tvbuff_t *tvb, int offset, int len)
{
    proto_tree_add_item(tree, hf_id, tvb, offset, len, ENC_ASCII|ENC_NA);
    return offset + len;
}

static int add_price(proto_tree *tree, int hf_id, tvbuff_t *tvb, int offset)
{
    uint32_t raw = tvb_get_ntohl(tvb, offset);
    gdouble val = bist_show_bigint_price ? raw / 10000.0 : (gdouble)raw;
    proto_tree_add_double(tree, hf_id, tvb, offset, 4, val);
    return offset + 4;
}

static int dissect_timestamp(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    uint32_t ns = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(tree, hf_bist_nanosecond, tvb, offset, 4, ns);
    return offset + 4;
}

static int dissect_quantity(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                            int offset, unsigned int len)
{
    uint64_t q = tvb_get_bits64(tvb, offset*8, len*8, ENC_BIG_ENDIAN);
    proto_tree_add_uint64(tree, hf_bist_quantity, tvb, offset, len, q);
    col_append_fstr(pinfo->cinfo, COL_INFO, "qty %" PRIu64 " ", q);
    return offset + len;
}

static int dissect_order_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                            int offset)
{
    uint64_t oid = tvb_get_ntoh64(tvb, offset);
    proto_tree_add_uint64(tree, hf_bist_order_id, tvb, offset, 8, oid);
    col_append_fstr(pinfo->cinfo, COL_INFO, "%" PRIu64 " ", oid);
    return offset + 8;
}

#define NEED(len) do { \
    if (tvb_reported_length_remaining(tvb, offset) < (len)) \
        goto done; \
} while (0)

static int
dissect_bist_itch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *bist_tree = NULL;
    gint        offset    = 0;
    uint8_t      type      = tvb_get_uint8(tvb, offset);


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "bist‑ITCH");
    const char *type_desc = val_to_str(type, message_types_val, "Unknown (0x%02x)");
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_str(pinfo->cinfo,   COL_INFO,  type_desc);

    if (tree) {
        ti = proto_tree_add_protocol_format(tree, proto_bist, tvb, 0, -1,
                                            "bist ITCH, %s", type_desc);
        bist_tree = proto_item_add_subtree(ti, ett_bist_itch);
    }

    if (bist_tree)
        proto_tree_add_uint(bist_tree, hf_bist_message_type, tvb, 0, 1, type);
    offset += 1;

    if (type == 'T') {
        offset = add_uint(bist_tree, hf_bist_second, tvb, offset, 4);
        goto done;
    }

    /* ------------------------------------------------------------------ */
    switch (type) {
    case 'R': {
        offset = dissect_timestamp(tvb, bist_tree, offset);
        offset = add_uint  (bist_tree, hf_bist_orderbook_id, tvb, offset, 4);
        offset = add_string(bist_tree, hf_bist_symbol,       tvb, offset, 32);
        offset = add_string(bist_tree, hf_bist_long_name,    tvb, offset, 32);
        offset = add_string(bist_tree, hf_bist_isin,         tvb, offset, 12);
        offset = add_uint  (bist_tree, hf_bist_financial_product, tvb, offset, 1);
        offset = add_string(bist_tree, hf_bist_trading_currency,  tvb, offset, 3);
        offset = add_uint  (bist_tree, hf_bist_price_decimals,     tvb, offset, 2);
        offset = add_uint  (bist_tree, hf_bist_nominal_decimals,   tvb, offset, 2);
        offset = add_uint  (bist_tree, hf_bist_odd_lot_size,       tvb, offset, 4);
        offset = add_uint  (bist_tree, hf_bist_round_lot_size,     tvb, offset, 4);
        offset = add_uint  (bist_tree, hf_bist_block_lot_size,     tvb, offset, 4);
        offset = add_uint  (bist_tree, hf_bist_nominal_value,      tvb, offset, 8);
        offset = add_uint  (bist_tree, hf_bist_number_of_leg,      tvb, offset, 1);
        offset = add_uint  (bist_tree, hf_bist_underlying_orderbook_id, tvb, offset, 4);
        offset = add_price (bist_tree, hf_bist_strike_price,       tvb, offset);
        offset = add_uint  (bist_tree, hf_bist_expiration_date,    tvb, offset, 4);
        offset = add_uint  (bist_tree, hf_bist_strike_price_decimals, tvb, offset, 2);
        offset = add_uint  (bist_tree, hf_bist_put_or_call,        tvb, offset, 1);
        NEED(1);
        offset = add_uint  (bist_tree, hf_bist_ranking_type,       tvb, offset, 1);
        break;
    }
    case 'L': {
        offset = dissect_timestamp(tvb, bist_tree, offset);
        offset = add_uint (bist_tree, hf_bist_orderbook_id, tvb, offset, 4);
        offset = add_uint (bist_tree, hf_bist_tick_size,    tvb, offset, 8);
        offset = add_price(bist_tree, hf_bist_price_from,   tvb, offset);
        offset = add_price(bist_tree, hf_bist_price_to,     tvb, offset);
        break;
    }
    case 'V': {
        offset = dissect_timestamp(tvb, bist_tree, offset);
        offset = add_uint (bist_tree, hf_bist_orderbook_id, tvb, offset, 4);
        proto_tree_add_item(bist_tree, hf_bist_short_sell_status, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        break;
    }
    case 'O': {
        offset = dissect_timestamp(tvb, bist_tree, offset);
        offset = add_uint  (bist_tree, hf_bist_orderbook_id, tvb, offset, 4);
        offset = add_string(bist_tree, hf_bist_state_name,   tvb, offset, 20);
        break;
    }
    case 'A': {
        offset = dissect_timestamp(tvb, bist_tree, offset);
        offset = dissect_order_id(tvb, pinfo, bist_tree, offset);
        offset = add_uint (bist_tree, hf_bist_orderbook_id, tvb, offset, 4);
        proto_tree_add_item(bist_tree, hf_bist_side, tvb, offset, 1, ENC_NA);
        offset += 1;
        NEED(4);
        offset = add_uint (bist_tree, hf_bist_ranking_seq, tvb, offset, 4);
        NEED(8);
        offset = dissect_quantity(tvb, pinfo, bist_tree, offset, 8);
        offset = add_price(bist_tree, hf_bist_price, tvb, offset);
        offset = add_uint (bist_tree, hf_bist_order_attributes, tvb, offset, 2);
        proto_tree_add_item(bist_tree, hf_bist_lot_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        NEED(8);
        offset = add_uint (bist_tree, hf_bist_ranking_time, tvb, offset, 8);
        break;
    }
    case 'E': {
        offset = dissect_timestamp(tvb, bist_tree, offset);
        offset = dissect_order_id(tvb, pinfo, bist_tree, offset);
        offset = add_uint (bist_tree, hf_bist_orderbook_id, tvb, offset, 4);
        proto_tree_add_item(bist_tree, hf_bist_side, tvb, offset, 1, ENC_NA);
        offset += 1;
        offset = dissect_quantity(tvb, pinfo, bist_tree, offset, 8);
        offset = add_uint (bist_tree, hf_bist_match_id, tvb, offset, 8);
        offset = add_uint (bist_tree, hf_bist_combo_group, tvb, offset, 4);
        /* Skip 14 reserved bytes */
        NEED(14);
        offset += 14;
        break;
    }
    case 'C': {
        offset = dissect_timestamp(tvb, bist_tree, offset);
        offset = dissect_order_id(tvb, pinfo, bist_tree, offset);
        offset = add_uint (bist_tree, hf_bist_orderbook_id, tvb, offset, 4);
        proto_tree_add_item(bist_tree, hf_bist_side, tvb, offset, 1, ENC_NA);
        offset += 1;
        offset = dissect_quantity(tvb, pinfo, bist_tree, offset, 8);
        offset = add_uint (bist_tree, hf_bist_match_id, tvb, offset, 8);
        offset = add_uint (bist_tree, hf_bist_combo_group, tvb, offset, 4);
        NEED(14);
        offset += 14;
        offset = add_price(bist_tree, hf_bist_price, tvb, offset);
        proto_tree_add_item(bist_tree, hf_bist_occured_cross, tvb, offset, 1, ENC_ASCII|ENC_NA);
        offset += 1;
        proto_tree_add_item(bist_tree, hf_bist_printable, tvb, offset, 1, ENC_ASCII|ENC_NA);
        offset += 1;
        break;
    }
    case 'D': {
        offset = dissect_timestamp(tvb, bist_tree, offset);
        offset = dissect_order_id(tvb, pinfo, bist_tree, offset);
        offset = add_uint(bist_tree, hf_bist_orderbook_id, tvb, offset, 4);
        proto_tree_add_item(bist_tree, hf_bist_side, tvb, offset, 1, ENC_NA);
        offset += 1;
        break;
    }
    case 'Y': {
        offset = dissect_timestamp(tvb, bist_tree, offset);
        offset = add_uint(bist_tree, hf_bist_orderbook_id, tvb, offset, 4);
        break;
    }
    case 'P': {
        offset = dissect_timestamp(tvb, bist_tree, offset);
        offset = add_uint (bist_tree, hf_bist_match_id, tvb, offset, 8);
        offset = add_uint (bist_tree, hf_bist_combo_group, tvb, offset, 4);
        proto_tree_add_item(bist_tree, hf_bist_side, tvb, offset, 1, ENC_NA);
        offset += 1;
        offset = dissect_quantity(tvb, pinfo, bist_tree, offset, 8);
        offset = add_uint (bist_tree, hf_bist_orderbook_id, tvb, offset, 4);
        offset = add_price(bist_tree, hf_bist_price, tvb, offset);
        NEED(14);
        offset += 14;
        proto_tree_add_item(bist_tree, hf_bist_printable, tvb, offset, 1, ENC_ASCII|ENC_NA);
        offset += 1;
        proto_tree_add_item(bist_tree, hf_bist_occured_cross, tvb, offset, 1, ENC_ASCII|ENC_NA);
        offset += 1;
        break;
    }
    case 'M': {
        offset = dissect_timestamp(tvb, bist_tree, offset);
        offset = add_uint(bist_tree, hf_bist_combo_orderbook_id, tvb, offset, 4);
        offset = add_uint(bist_tree, hf_bist_leg_order_book,   tvb, offset, 4);
        proto_tree_add_item(bist_tree, hf_bist_leg_side, tvb, offset, 1, ENC_NA);
        offset += 1;
        offset = add_uint(bist_tree, hf_bist_leg_ratio,       tvb, offset, 4);
        break;
    }
    default: {
        if (bist_tree)
            proto_tree_add_item(bist_tree, hf_bist_message, tvb, offset, -1, ENC_NA);
        offset = tvb_captured_length(tvb);
        break;
    }
    }


done:
    return tvb_captured_length(tvb);
}

#define HF_ENTRY(id, name, abbr, type, base, vals, blurb) \
    { &hf_bist_##id, { name, "bist-itch." abbr, type, base, vals, 0x0, blurb, HFILL } }

void proto_register_bist(void)
{
    static hf_register_info hf_bist[] = {
        HF_ENTRY(version,             "Version",                 "version",                 FT_UINT8,  BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(message_type,        "Message Type",            "message_type",            FT_UINT8,  BASE_HEX,    VALS(message_types_val),  NULL),
        HF_ENTRY(second,              "Second",                  "second",                  FT_UINT32, BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(nanosecond,          "Nanosecond",              "nanosecond",              FT_UINT32, BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(orderbook_id,        "Order Book ID",           "orderbook_id",            FT_UINT32, BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(order_id,            "Order ID",                "order_id",                FT_UINT64, BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(side,                "Side",                    "side",                    FT_UINT8,  BASE_HEX,    VALS(bist_itch_side_vals), NULL),
        HF_ENTRY(quantity,            "Quantity",                "quantity",                FT_UINT64, BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(price,               "Price",                   "price",                   FT_DOUBLE, BASE_NONE,   NULL,                     NULL),
        HF_ENTRY(match_id,            "Match ID",                "match_id",                FT_UINT64, BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(combo_group,         "Combo Group ID",          "combo_group",             FT_UINT32, BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(printable,           "Printable",               "printable",               FT_STRING, BASE_NONE,   NULL,                     NULL),
        HF_ENTRY(occured_cross,       "Occurred at Cross",       "occured_cross",           FT_STRING, BASE_NONE,   NULL,                     NULL),
        HF_ENTRY(event_code,          "Event Code",              "event_code",              FT_UINT8,  BASE_HEX,    VALS(bist_itch_event_vals), NULL),
        HF_ENTRY(symbol,              "Symbol",                  "symbol",                  FT_STRING, BASE_NONE,   NULL,                     NULL),
        HF_ENTRY(long_name,           "Long Name",               "long_name",               FT_STRING, BASE_NONE,   NULL,                     NULL),
        HF_ENTRY(isin,                "ISIN",                    "isin",                    FT_STRING, BASE_NONE,   NULL,                     NULL),
        HF_ENTRY(financial_product,   "Financial Product",       "financial_product",       FT_UINT8,  BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(trading_currency,    "Trading Currency",        "trading_currency",        FT_STRING, BASE_NONE,   NULL,                     NULL),
        HF_ENTRY(tick_size,           "Tick Size",               "tick_size",               FT_UINT64, BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(price_from,          "Price From",              "price_from",              FT_DOUBLE, BASE_NONE,   NULL,                     NULL),
        HF_ENTRY(price_to,            "Price To",                "price_to",                FT_DOUBLE, BASE_NONE,   NULL,                     NULL),
        HF_ENTRY(short_sell_status,   "Short Sell Status",       "short_sell_status",       FT_UINT8,  BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(state_name,          "State Name",              "state_name",              FT_STRING, BASE_NONE,   NULL,                     NULL),
        HF_ENTRY(ranking_seq,         "Ranking Sequence #",      "ranking_seq",             FT_UINT32, BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(ranking_time,        "Ranking Time (ns)",       "ranking_time",            FT_UINT64, BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(order_attributes,    "Order Attributes",        "order_attributes",        FT_UINT16, BASE_HEX,    NULL,                     NULL),
        HF_ENTRY(lot_type,            "Lot Type",                "lot_type",                FT_UINT8,  BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(price_decimals,      "Price Decimals",          "price_decimals",          FT_UINT8,  BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(nominal_decimals,    "Nominal Decimals",        "nominal_decimals",        FT_UINT8,  BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(odd_lot_size,        "Odd‑Lot Size",            "odd_lot_size",            FT_UINT32, BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(round_lot_size,      "Round‑Lot Size",          "round_lot_size",          FT_UINT32, BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(block_lot_size,      "Block‑Lot Size",          "block_lot_size",          FT_UINT32, BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(nominal_value,       "Nominal Value",           "nominal_value",           FT_UINT64, BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(number_of_leg,       "Number of Legs",          "number_of_leg",           FT_UINT8,  BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(underlying_orderbook_id,"Underlying Orderbook", "underlying_orderbook_id", FT_UINT32, BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(strike_price,        "Strike Price",            "strike_price",            FT_DOUBLE, BASE_NONE,   NULL,                     NULL),
        HF_ENTRY(expiration_date,     "Expiration Date",         "expiration_date",         FT_UINT32, BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(strike_price_decimals,"Strike Price Decimals",  "strike_price_decimals",   FT_UINT8,  BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(put_or_call,         "Put/Call",                "put_or_call",             FT_UINT8,  BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(ranking_type,        "Ranking Type",            "ranking_type",            FT_UINT8,  BASE_DEC,    NULL,                     NULL),
        HF_ENTRY(message,             "Raw Message",             "message",                 FT_BYTES,  BASE_NONE,   NULL,                     NULL),
        HF_ENTRY(leg_order_book,   "Leg Order Book ID", "leg_order_book", FT_UINT32,  BASE_DEC, NULL, NULL),
        HF_ENTRY(leg_side,         "Leg Side",          "leg_side",       FT_UINT8,   BASE_HEX, VALS(bist_itch_side_vals), NULL),
        HF_ENTRY(leg_ratio,        "Leg Ratio",         "leg_ratio",      FT_UINT32,  BASE_DEC, NULL, NULL),
        HF_ENTRY(bid_qty,          "Best Bid Qty",      "bid_qty",        FT_UINT64,  BASE_DEC, NULL, NULL),
        HF_ENTRY(ask_qty,          "Best Ask Qty",      "ask_qty", FT_UINT64,  BASE_DEC, NULL, NULL),
        HF_ENTRY(best_bid_price,   "Best Bid Price",    "best_bid_price", FT_DOUBLE,  BASE_NONE, NULL, NULL),
        HF_ENTRY(best_ask_price,   "Best Ask Price",    "best_ask_price", FT_DOUBLE,  BASE_NONE, NULL, NULL),
        HF_ENTRY(best_bid_qty,     "Next-Level Bid Qty","best_bid_qty",  FT_UINT64,  BASE_DEC, NULL, NULL),
     };
    static int *ett[] = { &ett_bist_itch };

    proto_bist = proto_register_protocol("BIST ITCH", "BIST‑ITCH", "bist_itch");
    proto_register_field_array(proto_bist, hf_bist, array_length(hf_bist));
    proto_register_subtree_array(ett,      array_length(ett));

    module_t *pref = prefs_register_protocol(proto_bist, NULL);
    prefs_register_bool_preference(pref, "show_bigint_price",
        "Show Prices as Decimals",
        "If enabled, 4‑byte price fields are divided by 10000 and shown as doubles.",
        &bist_show_bigint_price);

    bist_handle = register_dissector("bist-itch", dissect_bist_itch, proto_bist);
}

void proto_reg_handoff_bist(void)
{
    dissector_add_for_decode_as("moldudp64.payload", bist_handle);
    dissector_add_for_decode_as("moldudp.payload",   bist_handle);
}
