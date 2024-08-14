/* file-pcapng-ors.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/show_exception.h>
#include <epan/addr_resolv.h>

#include <epan/dissectors/file-pcapng.h>

static int proto_pcapng_ors = -1;

void proto_register_pcapng_ors(void);
void proto_reg_handoff_pcapng_ors(void);

static int hf_pcapng_option_code_ors_flow_map = -1;
static int hf_pcapng_option_code_ors_flow_map_option_value = -1;

static int hf_pcapng_option_code_ors_version = -1;
static int hf_pcapng_version_major = -1;
static int hf_pcapng_version_minor = -1;
static int hf_pcapng_version_build = -1;
static int hf_pcapng_version_rev = -1;
static int hf_pcapng_version_git_commit_hash = -1;
static int hf_pcapng_version_oran_fh_version = -1;

static int hf_pcapng_comp_header_method = -1;

static int hf_pcapng_option_code_ors_eaxcid_group = -1;
static int hf_pcapng_option_code_ors_eaxcid_group_option_value = -1;

static int hf_pcapng_option_code_ors_meta = -1;
static int hf_pcapng_option_code_ors_meta_option_value = -1;

static int hf_pcapng_option_code_ors_frame_characteristics = -1;
static int hf_pcapng_option_code_ors_frame_characteristics_option_value = -1;


#define BLOCK_ORS_VERSION               (0x80000000+43286+0)
#define BLOCK_ORS_META                  (0x80000000+43286+1)
#define BLOCK_ORS_FLOW_MAP              (0x80000000+43286+2)
#define BLOCK_ORS_EAXCID_GROUP          (0x80000000+43286+3)
#define BLOCK_ORS_FRAME_CHARACTERISTICS (0x80000000+43286+4)

#define BLOCK_ORS_VERSION_NAME               "ORS Version"
#define BLOCK_ORS_META_NAME                  "ORS Meta"
#define BLOCK_ORS_FLOW_MAP_NAME              "ORS Flow Map"
#define BLOCK_ORS_EAXCID_GROUP_NAME          "ORS EAXCID Group"
#define BLOCK_ORS_FRAME_CHARACTERISTICS_NAME "ORS Frame Characteristics"


static const value_string option_code_ors_info_vals[] = {
    { 0,   "End of Options" },
    { 1,   "Struct Start" },
    { 2,   "Struct End" },
    { 10,  "Version ORAN CUS Standard" },
    { 11,  "Version Stimulus" },
    { 12,  "Version Capture" },
    { 20,  "======== Flow Map DL Item ========" },  /* make the first entry in each port(?) start out */
    { 21,  "Flow Map UL Item" },
    { 25,  "eAXCID DU BW" },
    { 26,  "eAXCID BS BW" },
    { 27,  "eAXCID CC BW" },
    { 28,  "eAXCID RU BW" },
    { 30,  "UP Cmd Type" },
    { 31,  "UP Cmd Method" },
    { 32,  "UP Cmd BitWidth" },
    { 35,  "Num RBs" },
    { 36,  "Num Mu" },
    { 37,  "Carrier Freq" },
    { 38,  "Bandwidth" },
    { 39,  "Carrier Type" },
    { 40,  "Prach SCS" },
    { 41,  "Prach Format" },
    { 42,  "Prach Freq Offset" },
    { 50,  "eAXCiD Group DL Item" },
    { 51,  "eAXCiD Group UL Item" },
    { 52,  "eAXCiD Group Item Member" },
    { 53,  "NBIoT Freq Offset" },
    { 60,  "Frame Characteristics" },
    { 0, NULL }
};

/* Compression schemes */
#define COMP_NONE                  0
#define COMP_BLOCK_FP              1
#define COMP_BLOCK_SCALE           2
#define COMP_U_LAW                 3
#define COMP_MODULATION            4
#define BFP_AND_SELECTIVE_RE       5
#define MOD_COMPR_AND_SELECTIVE_RE 6

static const range_string ud_comp_header_meth[] = {
    {COMP_NONE,                  COMP_NONE,                  "No compression" },
    {COMP_BLOCK_FP,              COMP_BLOCK_FP,              "Block floating point compression" },
    {COMP_BLOCK_SCALE,           COMP_BLOCK_SCALE,           "Block scaling" },
    {COMP_U_LAW,                 COMP_U_LAW,                 "Mu - law" },
    {COMP_MODULATION,            COMP_MODULATION,            "Modulation compression" },
    {BFP_AND_SELECTIVE_RE,       BFP_AND_SELECTIVE_RE,       "BFP + selective RE sending" },
    {MOD_COMPR_AND_SELECTIVE_RE, MOD_COMPR_AND_SELECTIVE_RE, "mod-compr + selective RE sending" },
    {7, 15, "Reserved"},
    {0, 0, NULL}
};


/* Dissect this block type */
static void
dissect_ors_flow_map_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                            block_data_arg *argp)
{
    int offset = 0;

    /* All we have are options */
    dissect_options(tree, pinfo, BLOCK_ORS_FLOW_MAP, tvb, offset, argp->info->encoding, NULL);
}


static
void dissect_ors_common_option(proto_tree *option_tree, proto_item *option_item,
                               packet_info *pinfo _U_, tvbuff_t *tvb, int offset,
                               int unknown_option_hf,
                               uint32_t option_code, uint32_t option_length, unsigned encoding,
                               int hf)
{
    switch (option_code) {
        // Specific handling.
        case 31:
        {
            // UP Cmp Header
            uint8_t value = tvb_get_uint8(tvb, offset);
            proto_tree_add_item(option_tree, hf_pcapng_comp_header_method, tvb, offset, 1, encoding);
            proto_item_append_text(option_item, " (%s)", rval_to_str_const(value, ud_comp_header_meth, "Reserved"));
            break;
        }

        // General handling.
        case 0:
        case 1:
        case 2:
        case 10:
        case 11:
        case 12:
        case 20:
        case 21:
        case 25:
        case 26:
        case 27:
        case 28:
        case 29:
        case 30:
        case 32:
        case 35:
        case 36:
        case 37:
        case 38:
        case 39:
        case 40:
        case 41:
        case 42:
        case 50:
        case 51:
        case 52:
        case 53:
        case 60:
        {
            /* Just show all items as ints (fit into 64 bits) */
            uint64_t value;
            proto_tree_add_item_ret_uint64(option_tree, hf, tvb, offset, option_length, encoding, &value);
            proto_item_append_text(option_item, " (%" PRIu64 ")", value);
            offset += option_length;
            break;
        }

        default:
            /* Unknown option */
            proto_tree_add_item(option_tree, unknown_option_hf, tvb, offset, option_length, ENC_NA);
            offset += option_length;
            break;
    }
}


/* Dissect an individual option */
static
void dissect_ors_flow_map_option(proto_tree *option_tree, proto_item *option_item,
                                 packet_info *pinfo _U_, tvbuff_t *tvb, int offset,
                                 int unknown_option_hf,
                                 uint32_t option_code, uint32_t option_length, unsigned encoding)
{
    dissect_ors_common_option(option_tree, option_item, pinfo, tvb, offset, unknown_option_hf, option_code, option_length, encoding,
                              hf_pcapng_option_code_ors_flow_map_option_value);
}





/* Dissect this block type */
static void
dissect_ors_version_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                         block_data_arg *argp)
{
    int offset = 0;

    /* Major */
    proto_tree_add_item(tree, hf_pcapng_version_major, tvb, offset, 2, argp->info->encoding);
    offset += 2;
    /* Minor */
    proto_tree_add_item(tree, hf_pcapng_version_minor, tvb, offset, 2, argp->info->encoding);
    offset += 2;

    /* Build */
    proto_tree_add_item(tree, hf_pcapng_version_build, tvb, offset, 2, argp->info->encoding);
    offset += 2;
    /* Revision */
    proto_tree_add_item(tree, hf_pcapng_version_rev, tvb, offset, 2, argp->info->encoding);
    offset += 2;

    /* Git commit hash */
    proto_tree_add_item(tree, hf_pcapng_version_git_commit_hash, tvb, offset, 4, argp->info->encoding);
    offset += 4;

    /* All we have are options */
    dissect_options(tree, pinfo, BLOCK_ORS_VERSION, tvb, offset, argp->info->encoding, NULL);
}

/* Dissect an individual option */
static
void dissect_ors_version_option(proto_tree *option_tree, proto_item *option_item,
                                packet_info *pinfo _U_, tvbuff_t *tvb, int offset,
                                int unknown_option_hf,
                                uint32_t option_code, uint32_t option_length, unsigned encoding)
{
    switch (option_code) {
        case 10:
        {
            uint32_t oran_fh_cus_ver;
            proto_tree_add_item_ret_uint(option_tree, hf_pcapng_version_oran_fh_version, tvb, offset, option_length, encoding, &oran_fh_cus_ver);
            proto_item_append_text(option_item, " (ver = 0x%08x)", oran_fh_cus_ver);
            offset += option_length;
            break;
        }

        default:
            proto_tree_add_item(option_tree, unknown_option_hf, tvb, offset, option_length, ENC_NA);
            offset += option_length;
            break;
    }
}



/* Dissect this block type */
static void
dissect_ors_eaxcid_group_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                              block_data_arg *argp)
{
    int offset = 0;

    /* All we have are options */
    dissect_options(tree, pinfo, BLOCK_ORS_EAXCID_GROUP, tvb, offset, argp->info->encoding, NULL);
}

/* Dissect an individual option */
static
void dissect_ors_eaxcid_group_option(proto_tree *option_tree, proto_item *option_item,
                                     packet_info *pinfo _U_, tvbuff_t *tvb, int offset,
                                     int unknown_option_hf,
                                     uint32_t option_code, uint32_t option_length, unsigned encoding)
{
    dissect_ors_common_option(option_tree, option_item, pinfo, tvb, offset, unknown_option_hf, option_code, option_length, encoding,
                              hf_pcapng_option_code_ors_eaxcid_group_option_value);

}




/* Dissect this block type */
static void
dissect_ors_meta_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                      block_data_arg *argp)
{
    /* All we have are options */
    dissect_options(tree, pinfo, BLOCK_ORS_META, tvb, 0 /* offset */, argp->info->encoding, NULL);
}

/* Dissect an individual option */
static
void dissect_ors_meta_option(proto_tree *option_tree, proto_item *option_item,
                                     packet_info *pinfo _U_, tvbuff_t *tvb, int offset,
                                     int unknown_option_hf,
                                     uint32_t option_code, uint32_t option_length, unsigned encoding)
{
    dissect_ors_common_option(option_tree, option_item, pinfo, tvb, offset, unknown_option_hf, option_code, option_length, encoding,
                              hf_pcapng_option_code_ors_meta_option_value);

}



/* Dissect this block type */
static void
dissect_ors_frame_characteristics_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                                       block_data_arg *argp)
{
    int offset = 0;

    /* All we have are options */
    dissect_options(tree, pinfo, BLOCK_ORS_FRAME_CHARACTERISTICS, tvb, offset, argp->info->encoding, NULL);
}

/* Dissect an individual option */
static
void dissect_ors_frame_characteristics_option(proto_tree *option_tree, proto_item *option_item,
                                              packet_info *pinfo _U_, tvbuff_t *tvb, int offset,
                                              int unknown_option_hf,
                                               uint32_t option_code, uint32_t option_length, unsigned encoding)
{
    dissect_ors_common_option(option_tree, option_item, pinfo, tvb, offset, unknown_option_hf, option_code, option_length, encoding,
                              hf_pcapng_option_code_ors_frame_characteristics_option_value);
}



void
proto_register_pcapng_ors(void)
{
    static hf_register_info hf[] = {

        /* Version */
        { &hf_pcapng_option_code_ors_version,
            { "Code",                                      "pcapng.ors.version.options.option.code",
            FT_UINT16, BASE_DEC, VALS(option_code_ors_info_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pcapng_version_major,
            { "Major",                                      "pcapng.ors.version.major",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcapng_version_minor,
            { "Minor",                                      "pcapng.ors.version.minor",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcapng_version_build,
            { "Build",                                      "pcapng.ors.version.build",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcapng_version_rev,
            { "Rev",                                      "pcapng.ors.version.rev",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcapng_version_git_commit_hash,
            { "Git CommitHash",                           "pcapng.ors.version.git-commithash",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcapng_version_oran_fh_version,
            { "ORAN FH CUS Version",                      "pcapng.ors.version.oran-fh-cus-version",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },

        /* Flow Map */
        { &hf_pcapng_option_code_ors_flow_map,
            { "Code",                                      "pcapng.ors.flow-map.options.option.code",
            FT_UINT16, BASE_DEC, VALS(option_code_ors_info_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pcapng_option_code_ors_flow_map_option_value,
            { "Option Value",                                      "pcapng.ors.flow-map.option.code",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcapng_comp_header_method,
         {"UP Cmp Method", "pcapng.ors.comp-header-method",
          FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
          RVALS(ud_comp_header_meth), 0x0,
          "Compression method",
          HFILL}
         },

        /* eAXCID group */
        { &hf_pcapng_option_code_ors_eaxcid_group,
            { "Code",                                      "pcapng.ors.eaxcid-group.options.option.code",
            FT_UINT16, BASE_DEC, VALS(option_code_ors_info_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pcapng_option_code_ors_eaxcid_group_option_value,
            { "Option Value",                                      "pcapng.ors.eaxcid-group.option.code",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },


        /* Meta */
        { &hf_pcapng_option_code_ors_meta,
            { "Code",                                      "pcapng.ors.meta.options.option.code",
            FT_UINT16, BASE_DEC, VALS(option_code_ors_info_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pcapng_option_code_ors_meta_option_value,
            { "Option Value",                                      "pcapng.ors.meta.option.code",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },


        /* Frame Characteristics */
        { &hf_pcapng_option_code_ors_frame_characteristics,
            { "Code",                                      "pcapng.ors.frame-characteristics.options.option.code",
            FT_UINT16, BASE_DEC, VALS(option_code_ors_info_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pcapng_option_code_ors_frame_characteristics_option_value,
            { "Option Value",                                      "pcapng.ors.frame-characteristics.option.code",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

    };

    proto_pcapng_ors = proto_register_protocol("ORS", "ORS", "pcapng.ors");

    proto_register_field_array(proto_pcapng_ors, hf, array_length(hf));
}

void
proto_reg_handoff_pcapng_ors(void)
{
    /* Register with pcapng dissector */

    /* Version */
    static local_block_callback_info_t version_info;
    version_info.name = BLOCK_ORS_VERSION_NAME;
    /* Block-dissector function */
    version_info.dissector = dissect_ors_version_data;
    /* Options-related */
    version_info.option_root_hf = hf_pcapng_option_code_ors_version;
    version_info.option_vals = option_code_ors_info_vals;
    version_info.option_dissector = dissect_ors_version_option;
    register_pcapng_local_block_dissector(BLOCK_ORS_VERSION, &version_info);


    /* Flow Map */
    static local_block_callback_info_t flow_map_info;
    flow_map_info.name = BLOCK_ORS_FLOW_MAP_NAME;
    /* Block-dissector function */
    flow_map_info.dissector = dissect_ors_flow_map_data;
    /* Options-related */
    flow_map_info.option_root_hf = hf_pcapng_option_code_ors_flow_map;
    flow_map_info.option_vals = option_code_ors_info_vals;
    flow_map_info.option_dissector = dissect_ors_flow_map_option;
    register_pcapng_local_block_dissector(BLOCK_ORS_FLOW_MAP, &flow_map_info);

    /* eAXCID Group */
    static local_block_callback_info_t eaxcid_group_info;
    eaxcid_group_info.name = BLOCK_ORS_EAXCID_GROUP_NAME;
    /* Block-dissector function */
    eaxcid_group_info.dissector = dissect_ors_eaxcid_group_data;
    /* Options-related */
    eaxcid_group_info.option_root_hf = hf_pcapng_option_code_ors_eaxcid_group;
    eaxcid_group_info.option_vals = option_code_ors_info_vals;
    eaxcid_group_info.option_dissector = dissect_ors_eaxcid_group_option;
    register_pcapng_local_block_dissector(BLOCK_ORS_EAXCID_GROUP, &eaxcid_group_info);

    /* Meta */
    static local_block_callback_info_t meta_info;
    meta_info.name = BLOCK_ORS_META_NAME;
    /* Block-dissector function */
    meta_info.dissector = dissect_ors_meta_data;
    /* Options-related */
    meta_info.option_root_hf = hf_pcapng_option_code_ors_meta;
    meta_info.option_vals = option_code_ors_info_vals;
    meta_info.option_dissector = dissect_ors_meta_option;
    register_pcapng_local_block_dissector(BLOCK_ORS_META, &meta_info);

    /* Frame Characteristics  */
    static local_block_callback_info_t frame_characteristics_info;
    frame_characteristics_info.name = BLOCK_ORS_FRAME_CHARACTERISTICS_NAME;
    /* Block-dissector function */
    frame_characteristics_info.dissector = dissect_ors_frame_characteristics_data;
    /* Options-related */
    frame_characteristics_info.option_root_hf = hf_pcapng_option_code_ors_frame_characteristics;
    frame_characteristics_info.option_vals = option_code_ors_info_vals;
    frame_characteristics_info.option_dissector = dissect_ors_frame_characteristics_option;
    register_pcapng_local_block_dissector(BLOCK_ORS_FRAME_CHARACTERISTICS, &frame_characteristics_info);

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
