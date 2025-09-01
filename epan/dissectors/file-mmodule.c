/* file-mmodule.c
 *
 * M‑Module file handler dissector for .m files produced by Bachmann tooling
 *
 * Copyright 2025, Daniel Salloum <daniel.salloum@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN "MModule"

#include <epan/packet.h>
#include <wiretap/wtap.h>

#define RECORD_SIZE_DEFAULT  0x30

static dissector_handle_t mm_handle;
static dissector_handle_t elf_handle = NULL;

/* protocol and fields */
static int proto_m_module;
static int hf_tag;
static int hf_ftag;
static int hf_mod;
static int hf_mainv;
static int hf_subv;
static int hf_off;
static int hf_tstamp;
static int hf_vtype;
static int hf_vcode0;
static int hf_vcode1;
static int hf_vcode2;
static int hf_tot;
static int hf_nentries;
static int hf_ood;
static int hf_cksm;
static int hf_fna;
static int hf_len;
static int hf_elen;
static int hf_mentry;
static int hf_mcontent;


/* subtree array */
static int ett_m_module;
static int ett_m_module_entry_header;
static int ett_m_module_entry_content;

struct mentry_info {
    uint32_t       tag;
    uint32_t       start;
    uint32_t       len;
};


/* Tables */
static const value_string filetagmeaning[] = {
    {1 ,"Driver for M1 IO module"},
    //{2 ,"Regulator (old definition)"},
    {2 ,"VxWorks software module"},
    {3 ,"PLC 1131 software module"},
    {4 ,"Other module"},
    {5 ,"PLC library plm-file"},
    {6 ,"@deprecated since MSys 4.00R - Java software module"},
    {7 ,"Software service"},
    {8 ,"VxWorks software library"},
    {9 ,"Logic and firmware file"},
    {10,"M-Target software module"},
    { 0, NULL }
};

static const value_string modemeaning[] = {
    {1,"Object is in normal format (internal file)"},
    {2,"Object is compressed (internal file)"},
    {4,"Object is external (extra file)"},
    {0, NULL}
};

static const value_string vtypemeaning[] = {
    { 1,"Alpha-Version"},
    { 2,"Beta-Version"},
    { 3,"Release-Version"},
    {0, NULL}
};

static const value_string tagmeaning[] = {
    { 1  , "Object code"},
    { 2  , "Configuration data module.cfg" },
    { 3  , "Libraryxyz.lib"},
    { 4  , "Attribute specification"},
    { 5  , "Configuration rule module.bcr"},
    { 6  , "Java archive for modules xyz.jar"},
    { 10 , "Help infomodule.hlp" },
    { 11 , "Readme info module.txt" },
    { 12 , "Source code module.src" },
    { 13 , "Internal PLC library" },
    { 14 , "Packed C project sources module.tgz" },
    { 15 , "External PLC library module" },
    { 16 , "Software version requirement" },
    { 17 , "3S SDB-Filemodule.sdb" },
    { 19 , "Logic*.mch" },
    { 20 , "FIRMWARE*.h86" },
    { 21 , "Advanced test description*.xvd" },
    { 22 , "Compressed configuration rule*.zcr" },
    { 23 , "M-Target project*.mtp" },
    { 24 , "Any ZIP archive*.zip" },
    { 100, "Card/Driver type definition (CDI)"},
    { 200, "User-Defineable Objects"},
    {0, NULL}
};

static bool verify_checksum(tvbuff_t *tvb) //, packet_info *pinfo)
{
    uint32_t i=0, checksum=0, currsum=0;
    uint32_t file_len = (uint32_t)tvb_captured_length(tvb);
    //uint32_t * buf = (uint32_t *) wmem_alloc(pinfo->pool, sizeof(uint32_t) * (file_len/4));
    for (; i<(file_len/4) ; i++ ) {
        if (i == 11) {
                //currsum = buf[i];
                currsum = tvb_get_letohl(tvb,44);
        }
        else{
                //checksum += buf[i];
                checksum += tvb_get_letohl(tvb,i*4);
        }
    }
    checksum ^= 0x80000000;
    ws_debug("Given checksum: 0x%08x , Calculated checksum: 0x%08x\n",currsum,checksum);

    return checksum == currsum;
}

static bool verify_len(tvbuff_t *tvb)
{
    uint32_t file_len = (uint32_t)tvb_captured_length(tvb);
    uint32_t reported_len = tvb_get_letohl(tvb,0x20);
    ws_debug("reported len: 0x%08x , calculated file len: 0x%08x\n", reported_len, file_len);

    return file_len == reported_len;
}

static void add_mentry_m_module(proto_tree *subtree,tvbuff_t *tvb, packet_info *pinfo, int offset, int entrysz, struct mentry_info * mentry_table, int idx)
{
    proto_item * hdr = proto_tree_add_item(subtree, hf_mentry, tvb, offset, entrysz, ENC_NA);
    proto_tree * mentry_hdr = proto_item_add_subtree(hdr, ett_m_module_entry_header);
    proto_tree_add_item_ret_uint(mentry_hdr, hf_tag,      tvb, offset+ 0x00, 4, ENC_LITTLE_ENDIAN, &mentry_table[idx].tag);
    proto_tree_add_item(mentry_hdr, hf_mod,      tvb,  offset+0x04, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item_ret_uint(mentry_hdr, hf_len,      tvb,  offset+0x08, 4, ENC_LITTLE_ENDIAN, &mentry_table[idx].len);
    proto_tree_add_item_ret_uint(mentry_hdr, hf_off,      tvb,  offset+0x0c, 4, ENC_LITTLE_ENDIAN, &mentry_table[idx].start);
    proto_tree_add_item(mentry_hdr, hf_vtype,    tvb,  offset+0x10, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mentry_hdr, hf_vcode0,   tvb,  offset+0x14, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mentry_hdr, hf_vcode1,   tvb,  offset+0x18, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mentry_hdr, hf_vcode2,   tvb,  offset+0x1c, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mentry_hdr, hf_fna,      tvb,  offset+0x20, 13, ENC_ASCII);
    if (tvb_get_uint8(tvb,offset+0x20) != 0x0) {
        uint8_t * fname = tvb_get_stringzpad(pinfo->pool,tvb, offset+0x20, 13, ENC_UTF_8);
        proto_item_append_text(hdr,": %s",fname);
    }
}

static void setup_mentry_table_content(proto_tree *subtree, tvbuff_t *tvb , packet_info *pinfo, struct mentry_info *mentry_table, int idx)
{

    proto_item * blob = proto_tree_add_item(subtree, hf_mcontent, tvb, mentry_table[idx].start, mentry_table[idx].len , ENC_NA);
    proto_tree * blob_tree = proto_item_add_subtree(blob, ett_m_module_entry_content);
    tvbuff_t *sub_tvb = tvb_new_subset_length(tvb, mentry_table[idx].start, mentry_table[idx].len);
    if (mentry_table[idx].tag == 0x01) {
        if (elf_handle != NULL)
            call_dissector(elf_handle, sub_tvb, pinfo, blob_tree);
    }
    // If we want to do more sub-format parsing, add if conditions here
}

static int dissect_m_module(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    ws_debug("%s\n","dissect_m_module");
    int offset = 0;
    gint len = tvb_captured_length(tvb);
    uint32_t nentries, entsz;

    if (len < RECORD_SIZE_DEFAULT) {
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "M_Module");
    proto_item *ti = proto_tree_add_item(tree, proto_m_module, tvb, 0, len, ENC_NA);
    proto_tree *subtree = proto_item_add_subtree(ti, ett_m_module);

    // Extract file header
    proto_tree_add_item(subtree, hf_ftag,     tvb, 0x00, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_mainv,    tvb, 0x04, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_subv,     tvb, 0x08, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_tstamp,   tvb, 0x0c, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_vtype,    tvb, 0x10, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_vcode0,   tvb, 0x14, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_vcode1,   tvb, 0x18, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_vcode2,   tvb, 0x1c, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_tot,      tvb, 0x20, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item_ret_uint(subtree, hf_nentries, tvb, 0x24, 4, ENC_LITTLE_ENDIAN, &nentries);
    proto_tree_add_item_ret_uint(subtree, hf_ood,      tvb, 0x28, 4, ENC_LITTLE_ENDIAN, &entsz);
    proto_tree_add_item(subtree, hf_cksm,     tvb, 0x2c, 4, ENC_NA);

    struct mentry_info * mentry_table = (struct mentry_info *) wmem_alloc(pinfo->pool, sizeof(struct mentry_info) * nentries);

    for (uint32_t i = 0; i<nentries; i++){
        offset += entsz;
        add_mentry_m_module(subtree,tvb,pinfo,offset,entsz,mentry_table,i);
        setup_mentry_table_content(subtree,tvb,pinfo ,mentry_table, i);
    }

    // Returning record size, which in this case is entire m-file
    return len;
}

static bool dissect_m_module_heur(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
    ws_debug("%08x\n", tvb_get_letohl(tvb, 0xc0));

    if (verify_len(tvb) == false)
        return false;
    if (verify_checksum(tvb) == false)
        return false;

    int r = dissect_m_module(tvb, pinfo, tree, data);
    ws_debug("dissected length: %d\n", r);

    return r > 0;
}

void proto_register_m_module(void)
{
    /* set up header field registrations */
    static hf_register_info m_module_hf[] = {
      { &hf_ftag,     {"File Tag", "m_module.ftag", FT_UINT32,BASE_DEC,VALS(filetagmeaning),0x0,NULL,HFILL}},
      { &hf_tag,      {"Header Tag", "m_module.tag", FT_UINT32,BASE_DEC,VALS(tagmeaning),0x0,NULL,HFILL}},
      { &hf_mod,      {"Mode","m_module.mode",FT_UINT32,BASE_DEC,VALS(modemeaning),0x0,NULL,HFILL}},
      { &hf_mainv,    {"Main Version", "m_module.mainv",FT_UINT32,BASE_DEC,NULL,0x0,NULL,HFILL}},
      { &hf_len,      {"Length", "m_module.len",FT_UINT32, BASE_DEC,NULL,0x0,NULL,HFILL}},
      { &hf_subv,     {"Sub Version", "m_module.subv", FT_UINT32, BASE_DEC,NULL,0x0,NULL,HFILL}},
      { &hf_off,      {"File Offset","m_module.off",   FT_UINT32,BASE_DEC,NULL,0x0,NULL,HFILL}},
      { &hf_tstamp,   {"Timestamp","m_module.tstamp", FT_ABSOLUTE_TIME,ABSOLUTE_TIME_UTC,NULL,0x0,NULL,HFILL}},
      { &hf_vtype,    {"Version Type","m_module.vtype",FT_UINT32,BASE_DEC,VALS(vtypemeaning),0x0,NULL,HFILL}},
      { &hf_vcode0,   {"Version Code[0]","m_module.vcode0",   FT_UINT32,BASE_DEC,NULL,0x0,NULL,HFILL}},
      { &hf_vcode1,   {"Version Code[1]","m_module.vcode1",   FT_UINT32,BASE_DEC,NULL,0x0,NULL,HFILL}},
      { &hf_vcode2,   {"Version Code[2]","m_module.vcode2",   FT_UINT32,BASE_DEC,NULL,0x0,NULL,HFILL}},
      { &hf_ood,      {"Offset to object descriptor","m_module.ood",   FT_UINT32,BASE_DEC,NULL,0x0,NULL,HFILL}},
      { &hf_tot,      {"Total Bytes In File (for checksum)","m_module.tot",   FT_UINT32,BASE_DEC,NULL,0x0,NULL,HFILL}},
      { &hf_nentries, {"Entry Count","m_module.nentries",   FT_UINT32,BASE_DEC,NULL,0x0,NULL,HFILL}},
      { &hf_cksm,     {"Checksum","m_module.cksm",   FT_BYTES,SEP_SPACE,NULL,0x0,NULL,HFILL}},
      { &hf_fna,      {"Embedded file name","m_module.fname",FT_STRINGZ,BASE_NONE,NULL,0x0,NULL,HFILL}},
      { &hf_elen,     {"Entry Length","m_module.elen",   FT_UINT32,BASE_DEC,NULL,0x0,NULL,HFILL}},
      { &hf_mentry,   {"Header Entry","m_module.mentry",   FT_NONE,BASE_NONE,NULL,0x0,NULL,HFILL}},
      { &hf_mcontent, {"Content","m_module.content",   FT_NONE,BASE_NONE,NULL,0x0,NULL,HFILL}},
    };

    static int* ett[] = {
            &ett_m_module,
            &ett_m_module_entry_header,
            &ett_m_module_entry_content,
    };

    ws_debug("%s\n", "proto_register_m_module");
    proto_m_module = proto_register_protocol("M-Module", "M-Module", "m_module");

    proto_register_field_array(proto_m_module, m_module_hf, array_length(m_module_hf));
    proto_register_subtree_array(ett, array_length(ett));

    mm_handle = register_dissector("m_module", dissect_m_module, proto_m_module);
}

void proto_reg_handoff_m_module(void)
{
    ws_debug("%s\n", "proto_reg_handoff_m_module");

    elf_handle = find_dissector("elf");

    dissector_add_uint("wtap_encap", WTAP_ENCAP_MMODULE, mm_handle);

    dissector_add_string("media_type", "application/x-executable", mm_handle);
    dissector_add_string("media_type", "application/x-object", mm_handle);
    dissector_add_string("media_type", "application/octet-stream", mm_handle);
    // Returned when serving over python's http.server
    dissector_add_string("media_type", "application/vnd.wolfram.mathematica.package", mm_handle);

    heur_dissector_add("wtap_file", dissect_m_module_heur, "M-module file", "m_module_wtap", proto_m_module, HEURISTIC_ENABLE);
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
