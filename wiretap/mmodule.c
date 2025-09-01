/** @file
 *
 * Copyright 2025, Daniel Salloum <daniel.salloum@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "config.h"
#define WS_LOG_DOMAIN "MModuleFile"
#include "mmodule.h"

#include "wtap-int.h"
#include "file_wrappers.h"

static int mmodule_file_type_subtype = -1;
struct mmodule_phdr *mmodule;

void register_mmodule(void);

bool verify_checksum(FILE_T fh, uint32_t file_len, int *err, char **err_info)
{
    uint32_t i=0, currsum=0, checksum=0;
    uint32_t * buf = g_new(uint32_t,(file_len/4));
    if (file_seek(fh, 0x00, SEEK_SET, err) == -1){
        ws_debug("%s\n","couldn't seek while verifying checksum");
        return false;
    }
    if (!wtap_read_bytes_or_eof(fh, buf, file_len, err, err_info)) {
        return false;
    }

    for (; i<(file_len/4); i++){ // actually increments by 4 bytes
        if (i == 11) {
                currsum = buf[i];
        }
        else{
                checksum += buf[i];
        }
    }
    checksum ^= 0x80000000;
    ws_debug("Given checksum: 0x%08x , Calculated checksum: 0x%08x\n",currsum,checksum);
    if (file_seek(fh, 0x00, SEEK_SET, err) == -1){
        ws_debug("%s\n","couldn't reset seek");
        return false;
    }
    return checksum == currsum;
}

wtap_open_return_val mmodule_open(wtap *wth, int *err, char **err_info)
{
    uint32_t tmp;
    ws_debug("%s\n","start open");
    mmodule = g_new(struct mmodule_phdr, 1);
    ws_debug("%s\n","post alloc");
    if (file_seek(wth->fh, 0x00, SEEK_END, err) < 0) {
        ws_debug("%s\n","couldn't seek end");
        return false;
    }
    uint32_t file_len = (uint32_t) file_tell(wth->fh);
    if (file_seek(wth->fh, 0x20, SEEK_SET, err) == -1){
        ws_debug("%s\n","couldn't seek");
        return false;
    }
    if (!wtap_read_bytes_or_eof(wth->fh, &tmp, 4, err, err_info)) {
        return false;
    }
    uint32_t reported_len = GUINT32_FROM_LE(tmp);
    ws_debug("reported len: 0x%08x , calculated file len: 0x%08x\n",
            reported_len, file_len);
    if (reported_len != file_len) {
        return WTAP_OPEN_NOT_MINE;
    }

    if (verify_checksum(wth->fh,file_len,err,err_info) == false)
        return WTAP_OPEN_NOT_MINE;

    wth->file_type_subtype = mmodule_file_type_subtype;
    wth->file_encap = WTAP_ENCAP_MMODULE;
    wth->snapshot_length = 0;
    wth->file_tsprec = WTAP_TSPREC_SEC;
    wth->subtype_read = wtap_full_file_read;
    wth->subtype_seek_read = wtap_full_file_seek_read;
    // Explicitly set, in case code gets updated somewhere
    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
        return WTAP_OPEN_ERROR;
    }
    return WTAP_OPEN_MINE;
}

static const struct supported_block_type mmodule_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    // Use this if we break it up into different packets
    //{ WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
    { WTAP_BLOCK_PACKET, ONE_BLOCK_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info mmodule_info = {
    "Bachmann M-Module file", // description
    "m_module", // name
    "m", // extension
    NULL, // extra extensions
    false, // seek required?
    BLOCKS_SUPPORTED(mmodule_blocks_supported), // num blocks and block_type
    NULL,  // write support?
    NULL,  // open write support ?
    NULL   // We're not a lua writer
};

void register_mmodule(void)
{
    mmodule_file_type_subtype = wtap_register_file_type_subtype(&mmodule_info);

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("MMODULE",
                                                   mmodule_file_type_subtype);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
