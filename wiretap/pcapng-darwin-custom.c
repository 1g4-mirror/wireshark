/**
 * Support for Apple Legacy and Custom pcapng blocks and options
 * Copyright 2025, Omer Shapira <oesh@apple.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include "wtap-int.h"
#include "pcapng_module.h"
#include "wtap_opttypes.h"


/* pcapng: legacy DPEB (Darwin Process Event Block) file encoding. */
typedef struct pcapng_legacy_darwin_process_event_block_s {
    uint32_t process_id;
    /* Options */
}  pcapng_legacy_darwin_process_event_block_t;


/* Minimum DPEB size = minimum block size + size of fixed length portion of DPEB. */
 #define MIN_DPEB_SIZE    ((uint32_t)sizeof(pcapng_legacy_darwin_process_event_block_t))


static bool
pcapng_process_apple_legacy_block_option(wtapng_block_t *wblock, section_info_t *section_info _U_,
                                         uint16_t option_code, uint16_t option_length, const uint8_t *option_content,
                                         int *err, char **err_info)
{
    /* Handle the DPEB option content. */
    switch (option_code) {
        case(OPT_DPEB_NAME): /* dpeb_process_name */
            pcapng_process_string_option(wblock, option_code, option_length, option_content);
            break;
        case(OPT_DPEB_UUID): /* dpeb_process_uuid */
            pcapng_process_bytes_option(wblock, option_code, option_length, option_content);
            break;
        default:
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("pcapng: unrecognized option %u in legacy DPEB block", option_code);
            return false;
    }

    return true;
}

static bool
pcapng_read_darwin_legacy_block(wtap* wth, FILE_T fh, uint32_t block_size _U_,
    uint32_t block_content_size,
    section_info_t* section_info,
    wtapng_block_t* wblock,
    int* err, char** err_info)
{
    unsigned                                    opt_cont_buf_len;
    pcapng_legacy_darwin_process_event_block_t  dpeb;
    wtapng_darwin_process_event_mandatory_t     *dpeb_mand;
    wtapng_dpeb_lookup_info_t                   *dpeb_lookup_info;

    /* Is this block long enough to be a DPEB? */
    if (block_content_size < sizeof(uint32_t)) {
        /* Too short */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: total block length %u of an DPEB is too small (< %u)",
                                    block_content_size, MIN_DPEB_SIZE);
        return false;
    }

    /* If the DPEB index hasn't been initialized yet, do it now. */
    if ((dpeb_lookup_info = (wtapng_dpeb_lookup_info_t*)wth->darwin_opt) == NULL) {
        dpeb_lookup_info = g_new(wtapng_dpeb_lookup_info_t, 1);
        if (dpeb_lookup_info == NULL) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("pcapng: failed to allocate Darwin-specific info");
            return false;
        }
        dpeb_lookup_info->dpebs = g_hash_table_new(g_direct_hash, g_direct_equal);
        if (dpeb_lookup_info->dpebs == NULL) {
            g_free(dpeb_lookup_info);
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("pcapng: failed to allocate DPEB lookup info");
            return false;
        }
        dpeb_lookup_info->next_dpeb_id = 0;
        wth->darwin_opt = dpeb_lookup_info;
    }

    /* Read the fixed part of the DPEB */
    if (!wtap_read_bytes(fh, &dpeb, sizeof dpeb, err, err_info)) {
        ws_debug("failed to read packet data");
        return false;
    }

    /* Set wblock->block to a newly-allocated DPEB block. */
    wblock->block = wtap_block_create( WTAP_BLOCK_LEGACY_DARWIN_PROCESS_EVENT);

    /* We don't return these to the caller in pcapng_read(). */
    wblock->internal = true;

    /* Set the mandatory values for the block. */
    dpeb_mand = (wtapng_darwin_process_event_mandatory_t*)wtap_block_get_mandatory_data(wblock->block);
    if (section_info->byte_swapped) {
        dpeb_mand->process_id       = GUINT32_SWAP_LE_BE(dpeb.process_id);
    } else {
        dpeb_mand->process_id       = dpeb.process_id;
    }
    ws_debug("process_id %u", dpeb_mand->process_id);

    /* Process options. Note: encountering an unknown option should not discard the block. */
    opt_cont_buf_len = block_content_size - MIN_DPEB_SIZE; /* fixed part */
    pcapng_process_options(fh, wblock, section_info, opt_cont_buf_len,
                                pcapng_process_apple_legacy_block_option,
                                OPT_SECTION_BYTE_ORDER, err, err_info);

    /* Store the wblock->block in the lookup info */
    uint32_t dpeb_id = dpeb_lookup_info->next_dpeb_id ++;
    g_hash_table_insert(dpeb_lookup_info->dpebs, GUINT_TO_POINTER(dpeb_id), wblock->block);

    return true;
}


static bool
pcapng_parse_darwin_legacy_uint32(wtap_block_t block, unsigned option_code,
    unsigned option_length, const uint8_t* option_content,
    int* err, char** err_info)
{
    uint32_t uint32;

    if (option_length != 4) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: Darwin option 0x%hx length expected %u, actual %u",
            (uint16_t)option_code, 4, option_length);
        return false;
    }

    memcpy(&uint32, option_content, sizeof(uint32_t));
    wtap_block_add_uint32_option(block, option_code, uint32);

    ws_noisy("Processed integer option 0x%08x (len: %u) == %d", option_code, option_length, *(int32_t*)option_content);
    return true;
}

static bool
pcapng_parse_darwin_legacy_uint16(wtap_block_t block, unsigned option_code,
    unsigned option_length, const uint8_t* option_content,
    int* err, char** err_info)
{
    uint32_t uint32;
    if (option_length != 2) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: Darwin option 0x%hx length expected %u, actual %u",
            (uint16_t)option_code, 2, option_length);
        return false;
    }

    /* NOTE: Internally, the 16-bit options are stored as 32-bit.
     * Because of that, we are using uint32_t as the option length,
     * and not the real option length.
     */
    memcpy(&uint32, option_content, sizeof(uint32_t));
    wtap_block_add_uint32_option(block, option_code, uint32);

    ws_noisy("Processed integer option 0x%08x (len: %u) == %d", option_code, option_length, *(int32_t*)option_content);
    return true;
}

static bool
pcapng_parse_darwin_legacy_dpeb_id(wtap_block_t block, bool byte_swapped _U_,
    unsigned option_length, const uint8_t* option_content,
    int* err, char** err_info)
{
    return pcapng_parse_darwin_legacy_uint32(block, OPT_PKT_DARWIN_DPEB_ID, option_length, option_content, err, err_info);
}

static bool
pcapng_parse_darwin_legacy_svc_code(wtap_block_t block, bool byte_swapped _U_,
    unsigned option_length, const uint8_t* option_content,
    int* err, char** err_info)
{
    return pcapng_parse_darwin_legacy_uint32(block, OPT_PKT_DARWIN_SVC_CODE, option_length, option_content, err, err_info);
}

static bool
pcapng_parse_darwin_legacy_effective_dpeb_id(wtap_block_t block, bool byte_swapped _U_,
    unsigned option_length, const uint8_t* option_content,
    int* err, char** err_info)
{
    return pcapng_parse_darwin_legacy_uint32(block, OPT_PKT_DARWIN_EFFECTIVE_DPEB_ID, option_length, option_content, err, err_info);
}

static bool
pcapng_parse_darwin_legacy_md_flags(wtap_block_t block, bool byte_swapped _U_,
    unsigned option_length, const uint8_t* option_content,
    int* err, char** err_info)
{
    return pcapng_parse_darwin_legacy_uint32(block, OPT_PKT_DARWIN_MD_FLAGS, option_length, option_content, err, err_info);
}

static bool
pcapng_parse_darwin_legacy_flow_id(wtap_block_t block, bool byte_swapped _U_,
    unsigned option_length, const uint8_t* option_content,
    int* err, char** err_info)
{
    return pcapng_parse_darwin_legacy_uint32(block, OPT_PKT_DARWIN_FLOW_ID, option_length, option_content, err, err_info);
}

static bool
pcapng_parse_darwin_legacy_drop_reason(wtap_block_t block, bool byte_swapped _U_,
    unsigned option_length, const uint8_t* option_content,
    int* err, char** err_info)
{
    return pcapng_parse_darwin_legacy_uint32(block, OPT_PKT_DARWIN_DROP_REASON, option_length, option_content, err, err_info);
}

static bool
pcapng_parse_darwin_legacy_comp_gencnt(wtap_block_t block, bool byte_swapped _U_,
    unsigned option_length, const uint8_t* option_content,
    int* err, char** err_info)
{
    return pcapng_parse_darwin_legacy_uint32(block, OPT_PKT_DARWIN_COMP_GENCNT, option_length, option_content, err, err_info);
}

static bool
pcapng_parse_darwin_legacy_trace_tag(wtap_block_t block, bool byte_swapped _U_,
    unsigned option_length, const uint8_t* option_content,
    int* err, char** err_info)
{
    return pcapng_parse_darwin_legacy_uint16(block, OPT_PKT_DARWIN_TRACE_TAG, option_length, option_content, err, err_info);
}

static bool
pcapng_parse_darwin_legacy_drop_line(wtap_block_t block, bool byte_swapped _U_,
    unsigned option_length, const uint8_t* option_content,
    int* err, char** err_info)
{
    return pcapng_parse_darwin_legacy_uint16(block, OPT_PKT_DARWIN_DROP_LINE, option_length, option_content, err, err_info);
}

static bool
pcapng_parse_darwin_legacy_drop_func(wtap_block_t block, bool byte_swapped _U_,
    unsigned option_length, const uint8_t* option_content,
    int* err _U_, char** err_info _U_)
{
    wtap_opttype_return_val ret = wtap_block_add_string_option(block, OPT_PKT_DARWIN_DROP_FUNC, (const char*)option_content, option_length);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return false;

    ws_noisy("Processed string option 0x%08x (len: %u)", OPT_PKT_DARWIN_DROP_FUNC, option_length);
    return true;
}

void register_darwin(void)
{
    static pcapng_block_type_handler_t legacy = { BLOCK_TYPE_LEGACY_DPEB, pcapng_read_darwin_legacy_block, NULL, NULL, true, BT_INDEX_PBS};

    register_pcapng_block_type_handler(&legacy);

    register_pcapng_option_handler(BT_INDEX_PBS, OPT_PKT_DARWIN_DPEB_ID, pcapng_parse_darwin_legacy_dpeb_id, NULL, NULL);
    register_pcapng_option_handler(BT_INDEX_PBS, OPT_PKT_DARWIN_SVC_CODE, pcapng_parse_darwin_legacy_svc_code, NULL, NULL);
    register_pcapng_option_handler(BT_INDEX_PBS, OPT_PKT_DARWIN_EFFECTIVE_DPEB_ID, pcapng_parse_darwin_legacy_effective_dpeb_id, NULL, NULL);
    register_pcapng_option_handler(BT_INDEX_PBS, OPT_PKT_DARWIN_MD_FLAGS, pcapng_parse_darwin_legacy_md_flags, NULL, NULL);
    register_pcapng_option_handler(BT_INDEX_PBS, OPT_PKT_DARWIN_FLOW_ID, pcapng_parse_darwin_legacy_flow_id, NULL, NULL);
    register_pcapng_option_handler(BT_INDEX_PBS, OPT_PKT_DARWIN_TRACE_TAG, pcapng_parse_darwin_legacy_trace_tag, NULL, NULL);
    register_pcapng_option_handler(BT_INDEX_PBS, OPT_PKT_DARWIN_DROP_REASON, pcapng_parse_darwin_legacy_drop_reason, NULL, NULL);
    register_pcapng_option_handler(BT_INDEX_PBS, OPT_PKT_DARWIN_DROP_LINE, pcapng_parse_darwin_legacy_drop_line, NULL, NULL);
    register_pcapng_option_handler(BT_INDEX_PBS, OPT_PKT_DARWIN_COMP_GENCNT, pcapng_parse_darwin_legacy_comp_gencnt, NULL, NULL);
    register_pcapng_option_handler(BT_INDEX_PBS, OPT_PKT_DARWIN_DROP_FUNC, pcapng_parse_darwin_legacy_drop_func, NULL, NULL);
}
