/* packet-procmon.c
 * Routines for MS Procmon dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/tfs.h>
#include <wiretap/wtap.h>
#include "packet-ipv6.h"

#define PNAME  "MS Procmon Event"
#define PSNAME "MS Procmon"
#define PFNAME "procmon"

void proto_reg_handoff_procmon(void);
void proto_register_procmon(void);

/* Initialize the protocol and registered fields */
static int proto_procmon;

static int hf_procmon_process_index;
static int hf_procmon_thread_id;
static int hf_procmon_event_class;
static int hf_procmon_operation_type;
static int hf_procmon_duration;
static int hf_procmon_timestamp;
static int hf_procmon_event_result;
static int hf_procmon_stack_trace_depth;
static int hf_procmon_details_size;
static int hf_procmon_extra_details_offset;
static int hf_procmon_stack_trace_address;
static int hf_procmon_detail_data;
static int hf_procmon_extra_detail_data;
static int hf_procmon_process_operation;
static int hf_procmon_process_pid;
static int hf_procmon_process_path;
static int hf_procmon_process_path_size;
static int hf_procmon_process_path_is_ascii;
static int hf_procmon_process_path_char_count;
static int hf_procmon_process_commandline;
static int hf_procmon_process_commandline_size;
static int hf_procmon_process_commandline_is_ascii;
static int hf_procmon_process_commandline_char_count;
static int hf_procmon_process_thread_id;
static int hf_procmon_process_exit_status;
static int hf_procmon_process_kernel_time;
static int hf_procmon_process_user_time;
static int hf_procmon_process_working_set;
static int hf_procmon_process_peak_working_set;
static int hf_procmon_process_private_bytes;
static int hf_procmon_process_peak_private_bytes;
static int hf_procmon_process_image_base;
static int hf_procmon_process_image_size;
static int hf_procmon_process_parent_pid;
static int hf_procmon_process_curdir;
static int hf_procmon_process_curdir_size;
static int hf_procmon_process_curdir_is_ascii;
static int hf_procmon_process_curdir_char_count;
static int hf_procmon_process_environment;
static int hf_procmon_process_environment_char_count;
static int hf_procmon_registry_operation;
static int hf_procmon_registry_desired_access;
static int hf_procmon_registry_key;
static int hf_procmon_registry_key_size;
static int hf_procmon_registry_key_is_ascii;
static int hf_procmon_registry_key_char_count;
static int hf_procmon_registry_new_key;
static int hf_procmon_registry_new_key_size;
static int hf_procmon_registry_new_key_is_ascii;
static int hf_procmon_registry_new_key_char_count;
static int hf_procmon_registry_value;
static int hf_procmon_registry_value_size;
static int hf_procmon_registry_value_is_ascii;
static int hf_procmon_registry_value_char_count;
static int hf_procmon_registry_length;
static int hf_procmon_registry_information_class;
static int hf_procmon_registry_index;
static int hf_procmon_registry_type;
static int hf_procmon_registry_data_length;
static int hf_procmon_registry_key_information_class;
static int hf_procmon_filesystem_operation;
static int hf_procmon_filesystem_suboperation;
static int hf_procmon_filesystem_padding;
static int hf_procmon_filesystem_details;
static int hf_procmon_filesystem_path;
static int hf_procmon_filesystem_path_size;
static int hf_procmon_filesystem_path_is_ascii;
static int hf_procmon_filesystem_path_char_count;
static int hf_procmon_profiling_operation;
static int hf_procmon_network_operation;
static int hf_procmon_network_flags;
static int hf_procmon_network_flags_is_src_ipv4;
static int hf_procmon_network_flags_is_dst_ipv4;
static int hf_procmon_network_flags_tcp_udp;
static int hf_procmon_network_length;
static int hf_procmon_network_src_ipv4;
static int hf_procmon_network_src_ipv6;
static int hf_procmon_network_dest_ipv4;
static int hf_procmon_network_dest_ipv6;
static int hf_procmon_network_src_port;
static int hf_procmon_network_dest_port;
static int hf_procmon_network_padding;
static int hf_procmon_network_details;


/* Initialize the subtree pointers */
static int ett_procmon;
static int ett_procmon_header;
static int ett_procmon_stack_trace;
static int ett_procmon_process_event;
static int ett_procmon_process_path;
static int ett_procmon_process_commandline;
static int ett_procmon_process_curdir;
static int ett_procmon_registry_event;
static int ett_procmon_registry_key;
static int ett_procmon_registry_value;
static int ett_procmon_registry_new_key;
static int ett_procmon_filesystem_event;
static int ett_procmon_filesystem_path;
static int ett_procmon_profiling_event;
static int ett_procmon_network_event;
static int ett_procmon_network_flags;


static expert_field ei_procmon_unknown_event_class;
static expert_field ei_procmon_unknown_operation;

static dissector_handle_t procmon_handle;

#define PROCMON_EVENT_CLASS_TYPE_PROCESS     1
#define PROCMON_EVENT_CLASS_TYPE_REGISTRY    2
#define PROCMON_EVENT_CLASS_TYPE_FILE_SYSTEM 3
#define PROCMON_EVENT_CLASS_TYPE_PROFILING   4
#define PROCMON_EVENT_CLASS_TYPE_NETWORK     5

#define STRING_IS_ASCII_MASK   0x8000
#define STRING_CHAR_COUNT_MASK 0x7FFF

static void dissect_procmon_detail_string_info(tvbuff_t* tvb, proto_tree* tree, int offset,
                                            int hf_detail, int hf_detail_ascii, int hf_detail_char_count, int ett_detail, bool* is_ascii, uint16_t* char_count)
{
    proto_tree* detail_tree;
    proto_item* detail_item;
    uint32_t char_value;

    detail_item = proto_tree_add_item(tree, hf_detail, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    detail_tree = proto_item_add_subtree(detail_item, ett_detail);

    proto_tree_add_item_ret_boolean(detail_tree, hf_detail_ascii, tvb, offset, 2, ENC_LITTLE_ENDIAN, is_ascii);
    proto_tree_add_item_ret_uint(detail_tree, hf_detail_char_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &char_value);
    *char_count = (uint16_t)(char_value & STRING_CHAR_COUNT_MASK);
}

static int dissect_procmon_detail_string(tvbuff_t* tvb, proto_tree* tree, int offset, bool is_ascii, uint16_t char_count, int hf_detail_string)
{
        int char_size = is_ascii ? 1 : 2;
        int path_size = char_size * char_count;
        proto_tree_add_item(tree, hf_detail_string, tvb, offset, path_size, is_ascii ? ENC_ASCII : ENC_UTF_16|ENC_LITTLE_ENDIAN);
        return offset + path_size;
}


static const value_string event_class_vals[] = {
        { PROCMON_EVENT_CLASS_TYPE_PROCESS, "Process" },
        { PROCMON_EVENT_CLASS_TYPE_REGISTRY, "Registry" },
        { PROCMON_EVENT_CLASS_TYPE_FILE_SYSTEM, "File System" },
        { PROCMON_EVENT_CLASS_TYPE_PROFILING, "Profiling" },
        { PROCMON_EVENT_CLASS_TYPE_NETWORK, "Network" },
        { 0, NULL }
};

#define PROCMON_PROCESS_OPERATION_DEFINED           0x0000
#define PROCMON_PROCESS_OPERATION_CREATE            0x0001
#define PROCMON_PROCESS_OPERATION_EXIT              0x0002
#define PROCMON_PROCESS_OPERATION_THREAD_CREATE     0x0003
#define PROCMON_PROCESS_OPERATION_THREAD_EXIT       0x0004
#define PROCMON_PROCESS_OPERATION_LOAD_IMAGE        0x0005
#define PROCMON_PROCESS_OPERATION_THREAD_PROFILE    0x0006
#define PROCMON_PROCESS_OPERATION_PROCESS_START     0x0007
#define PROCMON_PROCESS_OPERATION_PROCESS_STATISTICS 0x0008
#define PROCMON_PROCESS_OPERATION_SYSTEM_STATISTICS 0x0009

static const value_string process_operation_vals[] = {
        { PROCMON_PROCESS_OPERATION_DEFINED,           "Process Defined" },
        { PROCMON_PROCESS_OPERATION_CREATE,            "Process Create" },
        { PROCMON_PROCESS_OPERATION_EXIT,              "Process Exit" },
        { PROCMON_PROCESS_OPERATION_THREAD_CREATE,     "Thread Create" },
        { PROCMON_PROCESS_OPERATION_THREAD_EXIT,       "Thread Exit" },
        { PROCMON_PROCESS_OPERATION_LOAD_IMAGE,        "Load Image" },
        { PROCMON_PROCESS_OPERATION_THREAD_PROFILE,    "Thread Profile" },
        { PROCMON_PROCESS_OPERATION_PROCESS_START,     "Process Start" },
        { PROCMON_PROCESS_OPERATION_PROCESS_STATISTICS, "Process Statistics" },
        { PROCMON_PROCESS_OPERATION_SYSTEM_STATISTICS, "System Statistics" },
        { 0, NULL }
};


static int dissect_procmon_process_event(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, uint32_t size, int operation_offset)
{
    proto_tree* process_tree;
    proto_item* operation_ti;
    uint32_t operation;
    const char* operation_str;

    process_tree = proto_tree_add_subtree(tree, tvb, offset, size, ett_procmon_process_event, NULL, "Process Data");
    operation_ti = proto_tree_add_item_ret_uint(process_tree, hf_procmon_process_operation, tvb, operation_offset, 2, ENC_LITTLE_ENDIAN, &operation);

    operation_str = try_val_to_str(operation, process_operation_vals);
    if (operation_str == NULL)
    {
        expert_add_info_format(pinfo, operation_ti, &ei_procmon_unknown_operation, "Unknown process operation: 0x%04x", operation);
        col_add_fstr(pinfo->cinfo, COL_INFO, "Process Operation: Unknown (0x%04x)", operation);
    }
    else
    {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Process Operation: %s", operation_str);
    }

    switch(operation) {
        case PROCMON_PROCESS_OPERATION_DEFINED:
        case PROCMON_PROCESS_OPERATION_CREATE:
        {
            bool is_path_ascii, is_commandline_ascii;
            uint16_t path_char_count, commandline_char_count;

            //Unknown fields
            offset += 4;
            proto_tree_add_item(process_tree, hf_procmon_process_pid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            //Unknown fields
            offset += 36;
            uint8_t unknown_size1 = tvb_get_uint8(tvb, offset);
            offset += 1;
            uint8_t unknown_size2 = tvb_get_uint8(tvb, offset);
            offset += 1;
            dissect_procmon_detail_string_info(tvb, process_tree, offset,
                hf_procmon_process_path_size, hf_procmon_process_path_is_ascii, hf_procmon_process_path_char_count, ett_procmon_process_path,
                &is_path_ascii, &path_char_count);
            offset += 2;
            dissect_procmon_detail_string_info(tvb, process_tree, offset,
                hf_procmon_process_commandline_size, hf_procmon_process_commandline_is_ascii, hf_procmon_process_commandline_char_count, ett_procmon_process_commandline,
                &is_commandline_ascii, &commandline_char_count);
            offset += 2;
            //Unknown fields
            offset += 2;
            offset += unknown_size1;
            offset += unknown_size2;
            offset = dissect_procmon_detail_string(tvb, process_tree, offset, is_path_ascii, path_char_count, hf_procmon_process_path);
            offset = dissect_procmon_detail_string(tvb, process_tree, offset, is_commandline_ascii, commandline_char_count, hf_procmon_process_commandline);

            break;
        }
        case PROCMON_PROCESS_OPERATION_EXIT:
        {
            proto_tree_add_item(process_tree, hf_procmon_process_exit_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(process_tree, hf_procmon_process_kernel_time, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(process_tree, hf_procmon_process_user_time, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(process_tree, hf_procmon_process_working_set, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(process_tree, hf_procmon_process_peak_working_set, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(process_tree, hf_procmon_process_private_bytes, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(process_tree, hf_procmon_process_peak_private_bytes, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            break;
        }
        case PROCMON_PROCESS_OPERATION_THREAD_CREATE:
        {
            proto_tree_add_item(process_tree, hf_procmon_process_thread_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        }
        case PROCMON_PROCESS_OPERATION_THREAD_EXIT:
        {
            //Unknown fields
            offset += 4;
            proto_tree_add_item(process_tree, hf_procmon_process_kernel_time, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(process_tree, hf_procmon_process_user_time, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            break;
        }
        case PROCMON_PROCESS_OPERATION_LOAD_IMAGE:
        {
            bool is_path_ascii;
            uint16_t path_char_count;

            if (pinfo->pseudo_header->procmon.system_bitness)
            {
                proto_tree_add_item(process_tree, hf_procmon_process_image_base, tvb, offset, 8, ENC_LITTLE_ENDIAN);
                offset += 8;
            }
            else
            {
                proto_tree_add_item(process_tree, hf_procmon_process_image_base, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
            }

            proto_tree_add_item(process_tree, hf_procmon_process_image_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            dissect_procmon_detail_string_info(tvb, process_tree, offset,
                hf_procmon_process_path_size, hf_procmon_process_path_is_ascii, hf_procmon_process_path_char_count, ett_procmon_process_path,
                &is_path_ascii, &path_char_count);
            offset += 2;
            //Unknown fields
            offset += 2;
            offset = dissect_procmon_detail_string(tvb, process_tree, offset, is_path_ascii, path_char_count, hf_procmon_process_path);
            break;
        }
        case PROCMON_PROCESS_OPERATION_THREAD_PROFILE:
            //Unknown
            break;
        case PROCMON_PROCESS_OPERATION_PROCESS_START:
        {
            bool is_commandline_ascii, is_curdir_ascii;
            uint16_t commandline_char_count, curdir_char_count;
            uint32_t environment_char_count;

            proto_tree_add_item(process_tree, hf_procmon_process_parent_pid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            dissect_procmon_detail_string_info(tvb, process_tree, offset,
                hf_procmon_process_commandline_size, hf_procmon_process_commandline_is_ascii, hf_procmon_process_commandline_char_count, ett_procmon_process_commandline,
                &is_commandline_ascii, &commandline_char_count);
            offset += 2;
            dissect_procmon_detail_string_info(tvb, process_tree, offset,
                hf_procmon_process_curdir_size, hf_procmon_process_curdir_is_ascii, hf_procmon_process_curdir_char_count, ett_procmon_process_curdir,
                &is_curdir_ascii, &curdir_char_count);
            offset += 2;
            proto_tree_add_item_ret_uint(process_tree, hf_procmon_process_environment_char_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &environment_char_count);
            offset += 4;
            offset = dissect_procmon_detail_string(tvb, process_tree, offset, is_commandline_ascii, commandline_char_count, hf_procmon_process_commandline);
            offset = dissect_procmon_detail_string(tvb, process_tree, offset, is_curdir_ascii, curdir_char_count, hf_procmon_process_curdir);
            proto_tree_add_item(process_tree, hf_procmon_process_environment, tvb, offset, environment_char_count*2, ENC_UTF_16|ENC_LITTLE_ENDIAN);
            break;
        }
        case PROCMON_PROCESS_OPERATION_PROCESS_STATISTICS:
            //Unknown
            break;
        case PROCMON_PROCESS_OPERATION_SYSTEM_STATISTICS:
            //Unknown
            break;
    }
    return offset;
}

#define PROCMON_REGISTRY_OPERATION_OPEN_KEY               0x0000
#define PROCMON_REGISTRY_OPERATION_CREATE_KEY             0x0001
#define PROCMON_REGISTRY_OPERATION_CLOSE_KEY              0x0002
#define PROCMON_REGISTRY_OPERATION_QUERY_KEY              0x0003
#define PROCMON_REGISTRY_OPERATION_SET_VALUE              0x0004
#define PROCMON_REGISTRY_OPERATION_QUERY_VALUE            0x0005
#define PROCMON_REGISTRY_OPERATION_ENUM_VALUE             0x0006
#define PROCMON_REGISTRY_OPERATION_ENUM_KEY               0x0007
#define PROCMON_REGISTRY_OPERATION_SET_INFO_KEY           0x0008
#define PROCMON_REGISTRY_OPERATION_DELETE_KEY             0x0009
#define PROCMON_REGISTRY_OPERATION_DELETE_VALUE           0x000A
#define PROCMON_REGISTRY_OPERATION_FLUSH_KEY              0x000B
#define PROCMON_REGISTRY_OPERATION_LOAD_KEY               0x000C
#define PROCMON_REGISTRY_OPERATION_UNLOAD_KEY             0x000D
#define PROCMON_REGISTRY_OPERATION_RENAME_KEY             0x000E
#define PROCMON_REGISTRY_OPERATION_QUERY_MULTIPLE_VALUE   0x000F
#define PROCMON_REGISTRY_OPERATION_SET_KEY_SECURITY       0x0010
#define PROCMON_REGISTRY_OPERATION_QUERY_KEY_SECURITY     0x0011

static const value_string registry_operation_vals[] = {
        { PROCMON_REGISTRY_OPERATION_OPEN_KEY,             "Open Key" },
        { PROCMON_REGISTRY_OPERATION_CREATE_KEY,           "Create Key" },
        { PROCMON_REGISTRY_OPERATION_CLOSE_KEY,            "Close Key" },
        { PROCMON_REGISTRY_OPERATION_QUERY_KEY,            "Query Key" },
        { PROCMON_REGISTRY_OPERATION_SET_VALUE,            "Set Value" },
        { PROCMON_REGISTRY_OPERATION_QUERY_VALUE,          "Query Value" },
        { PROCMON_REGISTRY_OPERATION_ENUM_VALUE,           "Enum Value" },
        { PROCMON_REGISTRY_OPERATION_ENUM_KEY,             "Enum Key" },
        { PROCMON_REGISTRY_OPERATION_SET_INFO_KEY,         "Set Info Key" },
        { PROCMON_REGISTRY_OPERATION_DELETE_KEY,           "Delete Key" },
        { PROCMON_REGISTRY_OPERATION_DELETE_VALUE,         "Delete Value" },
        { PROCMON_REGISTRY_OPERATION_FLUSH_KEY,            "Flush Key" },
        { PROCMON_REGISTRY_OPERATION_LOAD_KEY,             "Load Key" },
        { PROCMON_REGISTRY_OPERATION_UNLOAD_KEY,           "Unload Key" },
        { PROCMON_REGISTRY_OPERATION_RENAME_KEY,           "Rename Key" },
        { PROCMON_REGISTRY_OPERATION_QUERY_MULTIPLE_VALUE, "Query Multiple Value" },
        { PROCMON_REGISTRY_OPERATION_SET_KEY_SECURITY,     "Set Key Security" },
        { PROCMON_REGISTRY_OPERATION_QUERY_KEY_SECURITY,   "Query Key Security" },
        { 0, NULL }
};

static int dissect_procmon_registry_event(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, uint32_t size, int operation_offset)
{
    proto_tree* registry_tree;
    proto_item* operation_ti;
    uint32_t operation;
    const char* operation_str;
    bool is_value_ascii, is_new_value_ascii;
    uint16_t value_char_count, new_value_char_count;

    registry_tree = proto_tree_add_subtree(tree, tvb, offset, size, ett_procmon_registry_event, NULL, "Registry Data");
    operation_ti = proto_tree_add_item_ret_uint(registry_tree, hf_procmon_registry_operation, tvb, operation_offset, 2, ENC_LITTLE_ENDIAN, &operation);

    operation_str = try_val_to_str(operation, registry_operation_vals);
    if (operation_str == NULL)
    {
        expert_add_info_format(pinfo, operation_ti, &ei_procmon_unknown_operation, "Unknown registry operation: 0x%04x", operation);
        col_add_fstr(pinfo->cinfo, COL_INFO, "Registry Operation: Unknown (0x%04x)", operation);
    }
    else
    {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Registry Operation: %s", operation_str);
    }

    switch(operation) {
        case PROCMON_REGISTRY_OPERATION_OPEN_KEY:
        case PROCMON_REGISTRY_OPERATION_CREATE_KEY:
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_key_size, hf_procmon_registry_key_is_ascii, hf_procmon_registry_key_char_count, ett_procmon_registry_key,
                &is_value_ascii, &value_char_count);
            offset += 2;

            //Unknown fields
            offset += 2;

            proto_tree_add_item(registry_tree, hf_procmon_registry_desired_access, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_key);
            break;

        case PROCMON_REGISTRY_OPERATION_CLOSE_KEY:
        case PROCMON_REGISTRY_OPERATION_FLUSH_KEY:
        case PROCMON_REGISTRY_OPERATION_UNLOAD_KEY:
        case PROCMON_REGISTRY_OPERATION_DELETE_KEY:
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_key_size, hf_procmon_registry_key_is_ascii, hf_procmon_registry_key_char_count, ett_procmon_registry_key,
                &is_value_ascii, &value_char_count);
            offset += 2;
            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_key);
            break;

        case PROCMON_REGISTRY_OPERATION_QUERY_KEY:
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_key_size, hf_procmon_registry_key_is_ascii, hf_procmon_registry_key_char_count, ett_procmon_registry_key,
                &is_value_ascii, &value_char_count);
            offset += 2;

            //Unknown fields
            offset += 2;

            proto_tree_add_item(registry_tree, hf_procmon_registry_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(registry_tree, hf_procmon_registry_information_class, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_key);
            break;

        case PROCMON_REGISTRY_OPERATION_QUERY_VALUE:
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_value_size, hf_procmon_registry_value_is_ascii, hf_procmon_registry_value_char_count, ett_procmon_registry_value,
                &is_value_ascii, &value_char_count);
            offset += 2;

            //Unknown fields
            offset += 2;

            proto_tree_add_item(registry_tree, hf_procmon_registry_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(registry_tree, hf_procmon_registry_information_class, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_value);
            break;

        case PROCMON_REGISTRY_OPERATION_ENUM_KEY:
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_key_size, hf_procmon_registry_key_is_ascii, hf_procmon_registry_key_char_count, ett_procmon_registry_key,
                &is_value_ascii, &value_char_count);
            offset += 2;

            //Unknown fields
            offset += 2;

            proto_tree_add_item(registry_tree, hf_procmon_registry_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(registry_tree, hf_procmon_registry_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(registry_tree, hf_procmon_registry_information_class, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_key);
            break;

        case PROCMON_REGISTRY_OPERATION_ENUM_VALUE:
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_value_size, hf_procmon_registry_value_is_ascii, hf_procmon_registry_value_char_count, ett_procmon_registry_value,
                &is_value_ascii, &value_char_count);
            offset += 2;

            //Unknown fields
            offset += 2;

            proto_tree_add_item(registry_tree, hf_procmon_registry_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(registry_tree, hf_procmon_registry_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(registry_tree, hf_procmon_registry_information_class, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_value);
            break;

        case PROCMON_REGISTRY_OPERATION_SET_VALUE:
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_value_size, hf_procmon_registry_value_is_ascii, hf_procmon_registry_value_char_count, ett_procmon_registry_value,
                &is_value_ascii, &value_char_count);
            offset += 2;

            //Unknown fields
            offset += 2;

            proto_tree_add_item(registry_tree, hf_procmon_registry_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(registry_tree, hf_procmon_registry_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(registry_tree, hf_procmon_registry_data_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_value);

            break;
        case PROCMON_REGISTRY_OPERATION_SET_INFO_KEY:
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_key_size, hf_procmon_registry_key_is_ascii, hf_procmon_registry_key_char_count, ett_procmon_registry_key,
                &is_value_ascii, &value_char_count);
            offset += 2;

            //Unknown fields
            offset += 2;

            proto_tree_add_item(registry_tree, hf_procmon_registry_key_information_class, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            //Unknown fields
            offset += 4;

            proto_tree_add_item(registry_tree, hf_procmon_registry_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            //Unknown fields
            offset += 2;

            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_key);
            break;

        case PROCMON_REGISTRY_OPERATION_DELETE_VALUE:
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_value_size, hf_procmon_registry_value_is_ascii, hf_procmon_registry_value_char_count, ett_procmon_registry_value,
                &is_value_ascii, &value_char_count);
            offset += 2;

            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_value);
            break;

        case PROCMON_REGISTRY_OPERATION_LOAD_KEY:
        case PROCMON_REGISTRY_OPERATION_RENAME_KEY:
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_key_size, hf_procmon_registry_key_is_ascii, hf_procmon_registry_key_char_count, ett_procmon_registry_key,
                &is_value_ascii, &value_char_count);
            offset += 2;
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_new_key_size, hf_procmon_registry_new_key_is_ascii, hf_procmon_registry_new_key_char_count, ett_procmon_registry_new_key,
                &is_new_value_ascii, &new_value_char_count);
            offset += 2;
            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_key);
            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_new_value_ascii, new_value_char_count, hf_procmon_registry_new_key);
            break;

        case PROCMON_REGISTRY_OPERATION_QUERY_MULTIPLE_VALUE:
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_value_size, hf_procmon_registry_value_is_ascii, hf_procmon_registry_value_char_count, ett_procmon_registry_value,
                &is_value_ascii, &value_char_count);
            offset += 2;

            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_value);
            break;

        case PROCMON_REGISTRY_OPERATION_SET_KEY_SECURITY:
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_key_size, hf_procmon_registry_key_is_ascii, hf_procmon_registry_key_char_count, ett_procmon_registry_key,
                &is_value_ascii, &value_char_count);
            offset += 2;
            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_key);
            break;

        case PROCMON_REGISTRY_OPERATION_QUERY_KEY_SECURITY:
            dissect_procmon_detail_string_info(tvb, registry_tree, offset,
                hf_procmon_registry_key_size, hf_procmon_registry_key_is_ascii, hf_procmon_registry_key_char_count, ett_procmon_registry_key,
                &is_value_ascii, &value_char_count);
            offset += 2;
            offset = dissect_procmon_detail_string(tvb, registry_tree, offset, is_value_ascii, value_char_count, hf_procmon_registry_key);
            break;
    }

    return offset;
}

#define PROCMON_FILESYSTEM_OPERATION_VOLUME_DISMOUNT             0
#define PROCMON_FILESYSTEM_OPERATION_VOLUME_MOUNT                1
#define PROCMON_FILESYSTEM_OPERATION_FASTIO_MDL_WRITE_COMPLETE   2
#define PROCMON_FILESYSTEM_OPERATION_WRITE_FILE2                 3
#define PROCMON_FILESYSTEM_OPERATION_FASTIO_MDL_READ_COMPLETE    4
#define PROCMON_FILESYSTEM_OPERATION_READ_FILE2                  5
#define PROCMON_FILESYSTEM_OPERATION_QUERY_OPEN                  6
#define PROCMON_FILESYSTEM_OPERATION_FASTIO_CHECK_IF_POSSIBLE    7
#define PROCMON_FILESYSTEM_OPERATION_IRP_MJ_12                   8
#define PROCMON_FILESYSTEM_OPERATION_IRP_MJ_11                   9
#define PROCMON_FILESYSTEM_OPERATION_IRP_MJ_10                   10
#define PROCMON_FILESYSTEM_OPERATION_IRP_MJ_9                    11
#define PROCMON_FILESYSTEM_OPERATION_IRP_MJ_8                    12
#define PROCMON_FILESYSTEM_OPERATION_FASTIO_NOTIFY_STREAM_FO_CREATION 13
#define PROCMON_FILESYSTEM_OPERATION_FASTIO_RELEASE_FOR_CC_FLUSH      14
#define PROCMON_FILESYSTEM_OPERATION_FASTIO_ACQUIRE_FOR_CC_FLUSH      15
#define PROCMON_FILESYSTEM_OPERATION_FASTIO_RELEASE_FOR_MOD_WRITE    16
#define PROCMON_FILESYSTEM_OPERATION_FASTIO_ACQUIRE_FOR_MOD_WRITE    17
#define PROCMON_FILESYSTEM_OPERATION_FASTIO_RELEASE_FOR_SECTION_SYNCHRONIZATION 18
#define PROCMON_FILESYSTEM_OPERATION_CREATE_FILE_MAPPING                 19
#define PROCMON_FILESYSTEM_OPERATION_CREATE_FILE                         20
#define PROCMON_FILESYSTEM_OPERATION_CREATE_PIPE                         21
#define PROCMON_FILESYSTEM_OPERATION_IRP_MJ_CLOSE                        22
#define PROCMON_FILESYSTEM_OPERATION_READ_FILE                         23
#define PROCMON_FILESYSTEM_OPERATION_WRITE_FILE                        24
#define PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE           25
#define PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE             26
#define PROCMON_FILESYSTEM_OPERATION_QUERY_EA_FILE                    27
#define PROCMON_FILESYSTEM_OPERATION_SET_EA_FILE                      28
#define PROCMON_FILESYSTEM_OPERATION_FLUSH_BUFFERS_FILE              29
#define PROCMON_FILESYSTEM_OPERATION_QUERY_VOLUME_INFORMATION        30
#define PROCMON_FILESYSTEM_OPERATION_SET_VOLUME_INFORMATION          31
#define PROCMON_FILESYSTEM_OPERATION_DIRECTORY_CONTROL              32
#define PROCMON_FILESYSTEM_OPERATION_FILE_SYSTEM_CONTROL           33
#define PROCMON_FILESYSTEM_OPERATION_DEVICE_IO_CONTROL         34
#define PROCMON_FILESYSTEM_OPERATION_INTERNAL_DEVICE_IO_CONTROL 35
#define PROCMON_FILESYSTEM_OPERATION_SHUTDOWN                   36
#define PROCMON_FILESYSTEM_OPERATION_LOCK_UNLOCK_FILE           37
#define PROCMON_FILESYSTEM_OPERATION_CLOSE_FILE                38
#define PROCMON_FILESYSTEM_OPERATION_CREATE_MAIL_SLOT          39
#define PROCMON_FILESYSTEM_OPERATION_QUERY_SECURITY_FILE       40
#define PROCMON_FILESYSTEM_OPERATION_SET_SECURITY_FILE         41
#define PROCMON_FILESYSTEM_OPERATION_POWER                     42
#define PROCMON_FILESYSTEM_OPERATION_SYSTEM_CONTROL            43
#define PROCMON_FILESYSTEM_OPERATION_DEVICE_CHANGE             44
#define PROCMON_FILESYSTEM_OPERATION_QUERY_FILE_QUOTA          45
#define PROCMON_FILESYSTEM_OPERATION_SET_FILE_QUOTA            46
#define PROCMON_FILESYSTEM_OPERATION_PLUG_AND_PLAY             47

static const value_string filesystem_operation_vals[] = {
        { PROCMON_FILESYSTEM_OPERATION_VOLUME_DISMOUNT,             "Volume Dismount" },
        { PROCMON_FILESYSTEM_OPERATION_VOLUME_MOUNT,                "Volume Mount" },
        { PROCMON_FILESYSTEM_OPERATION_FASTIO_MDL_WRITE_COMPLETE,   "Fast I/O MDL Write Complete" },
        { PROCMON_FILESYSTEM_OPERATION_WRITE_FILE2,                 "Write File 2" },
        { PROCMON_FILESYSTEM_OPERATION_FASTIO_MDL_READ_COMPLETE,    "Fast I/O MDL Read Complete" },
        { PROCMON_FILESYSTEM_OPERATION_READ_FILE2,                  "Read File 2" },
        { PROCMON_FILESYSTEM_OPERATION_QUERY_OPEN,                  "Query Open" },
        { PROCMON_FILESYSTEM_OPERATION_FASTIO_CHECK_IF_POSSIBLE,    "Fast I/O Check If Possible" },
        { PROCMON_FILESYSTEM_OPERATION_IRP_MJ_12,                   "IRP_MJ_CLEANUP" },
        { PROCMON_FILESYSTEM_OPERATION_IRP_MJ_11,                   "IRP_MJ_SET_INFORMATION" },
        { PROCMON_FILESYSTEM_OPERATION_IRP_MJ_10,                   "IRP_MJ_QUERY_INFORMATION" },
        { PROCMON_FILESYSTEM_OPERATION_IRP_MJ_9,                    "IRP_MJ_FLUSH_BUFFERS" },
        { PROCMON_FILESYSTEM_OPERATION_IRP_MJ_8,                    "IRP_MJ_DIRECTORY_CONTROL" },
        { PROCMON_FILESYSTEM_OPERATION_FASTIO_NOTIFY_STREAM_FO_CREATION, "Fast I/O Notify Stream File Object Creation" },
        { PROCMON_FILESYSTEM_OPERATION_FASTIO_RELEASE_FOR_CC_FLUSH,      "Fast I/O Release For Cache Manager Flush" },
        { PROCMON_FILESYSTEM_OPERATION_FASTIO_ACQUIRE_FOR_CC_FLUSH,      "Fast I/O Acquire For Cache Manager Flush" },
        { PROCMON_FILESYSTEM_OPERATION_FASTIO_RELEASE_FOR_MOD_WRITE,    "Fast I/O Release For Modified Write" },
        { PROCMON_FILESYSTEM_OPERATION_FASTIO_ACQUIRE_FOR_MOD_WRITE,    "Fast I/O Acquire For Modified Write" },
        { PROCMON_FILESYSTEM_OPERATION_FASTIO_RELEASE_FOR_SECTION_SYNCHRONIZATION, "Fast I/O Release For Section Synchronization" },
        { PROCMON_FILESYSTEM_OPERATION_CREATE_FILE_MAPPING,                 "Create File Mapping" },
        { PROCMON_FILESYSTEM_OPERATION_CREATE_FILE,                         "Create File" },
        { PROCMON_FILESYSTEM_OPERATION_CREATE_PIPE,                         "Create Pipe" },
        { PROCMON_FILESYSTEM_OPERATION_IRP_MJ_CLOSE,                        "IRP_MJ_CLOSE" },
        { PROCMON_FILESYSTEM_OPERATION_READ_FILE,                         "Read File" },
        { PROCMON_FILESYSTEM_OPERATION_WRITE_FILE,                        "Write File" },
        { PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE,           "Query Information File" },
        { PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE,             "Set Information File" },
        { PROCMON_FILESYSTEM_OPERATION_QUERY_EA_FILE,                    "Query EA File" },
        { PROCMON_FILESYSTEM_OPERATION_SET_EA_FILE,                      "Set EA File" },
        { PROCMON_FILESYSTEM_OPERATION_FLUSH_BUFFERS_FILE,              "Flush Buffers File" },
        { PROCMON_FILESYSTEM_OPERATION_QUERY_VOLUME_INFORMATION,        "Query Volume Information" },
        { PROCMON_FILESYSTEM_OPERATION_SET_VOLUME_INFORMATION,          "Set Volume Information" },
        { PROCMON_FILESYSTEM_OPERATION_DIRECTORY_CONTROL,              "Directory Control" },
        { PROCMON_FILESYSTEM_OPERATION_FILE_SYSTEM_CONTROL,           "File System Control" },
        { PROCMON_FILESYSTEM_OPERATION_DEVICE_IO_CONTROL,         "Device I/O Control" },
        { PROCMON_FILESYSTEM_OPERATION_INTERNAL_DEVICE_IO_CONTROL, "Internal Device I/O Control" },
        { PROCMON_FILESYSTEM_OPERATION_SHUTDOWN,                   "Shutdown" },
        { PROCMON_FILESYSTEM_OPERATION_LOCK_UNLOCK_FILE,           "Lock/Unlock File" },
        { PROCMON_FILESYSTEM_OPERATION_CLOSE_FILE,                "Close File" },
        { PROCMON_FILESYSTEM_OPERATION_CREATE_MAIL_SLOT,          "Create Mail Slot" },
        { PROCMON_FILESYSTEM_OPERATION_QUERY_SECURITY_FILE,       "Query Security File" },
        { PROCMON_FILESYSTEM_OPERATION_SET_SECURITY_FILE,         "Set Security File" },
        { PROCMON_FILESYSTEM_OPERATION_POWER,                     "Power" },
        { PROCMON_FILESYSTEM_OPERATION_SYSTEM_CONTROL,            "System Control" },
        { PROCMON_FILESYSTEM_OPERATION_DEVICE_CHANGE,             "Device Change" },
        { PROCMON_FILESYSTEM_OPERATION_QUERY_FILE_QUOTA,          "Query File Quota" },
        { PROCMON_FILESYSTEM_OPERATION_SET_FILE_QUOTA,            "Set File Quota" },
        { PROCMON_FILESYSTEM_OPERATION_PLUG_AND_PLAY,             "Plug and Play" },
        { 0, NULL }
};

static int dissect_procmon_filesystem_event(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, uint32_t size, int operation_offset)
{
    proto_tree* filesystem_tree;
    proto_item* operation_ti;
    uint32_t operation;
    const char* operation_str;
    int size_of_pointer;
    bool is_path_ascii;
    uint16_t path_char_count;

    filesystem_tree = proto_tree_add_subtree(tree, tvb, offset, size, ett_procmon_filesystem_event, NULL, "File System Data");
    operation_ti = proto_tree_add_item_ret_uint(filesystem_tree, hf_procmon_filesystem_operation, tvb, operation_offset, 2, ENC_LITTLE_ENDIAN, &operation);

    operation_str = try_val_to_str(operation, filesystem_operation_vals);
    if (operation_str == NULL)
    {
        expert_add_info_format(pinfo, operation_ti, &ei_procmon_unknown_operation, "Unknown file system operation: 0x%04x", operation);
        col_add_fstr(pinfo->cinfo, COL_INFO, "File System Operation: Unknown (0x%04x)", operation);
    }
    else
    {
        col_add_fstr(pinfo->cinfo, COL_INFO, "File System Operation: %s", operation_str);
    }

    proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_suboperation, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_padding, tvb, offset, 3, ENC_NA);
    offset += 3;

    if (pinfo->pseudo_header->procmon.system_bitness)
    {
        size_of_pointer = 8;
    }
    else
    {
        size_of_pointer = 4;
    }
    proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_details, tvb, offset, 5*size_of_pointer+20, ENC_NA);
    offset += (5 * size_of_pointer + 20);
    dissect_procmon_detail_string_info(tvb, filesystem_tree, offset,
        hf_procmon_filesystem_path_size, hf_procmon_filesystem_path_is_ascii, hf_procmon_filesystem_path_char_count, ett_procmon_filesystem_path,
        &is_path_ascii, &path_char_count);
    offset += 2;
    proto_tree_add_item(filesystem_tree, hf_procmon_filesystem_padding, tvb, offset, 2, ENC_NA);
    offset += 2;
    offset = dissect_procmon_detail_string(tvb, filesystem_tree, offset, is_path_ascii, path_char_count, hf_procmon_filesystem_path);

    switch(operation)
    {
        case PROCMON_FILESYSTEM_OPERATION_VOLUME_DISMOUNT:
        case PROCMON_FILESYSTEM_OPERATION_VOLUME_MOUNT:
        case PROCMON_FILESYSTEM_OPERATION_FASTIO_MDL_WRITE_COMPLETE:
        case PROCMON_FILESYSTEM_OPERATION_WRITE_FILE2:
        case PROCMON_FILESYSTEM_OPERATION_FASTIO_MDL_READ_COMPLETE:
        case PROCMON_FILESYSTEM_OPERATION_READ_FILE2:
        case PROCMON_FILESYSTEM_OPERATION_QUERY_OPEN:
        case PROCMON_FILESYSTEM_OPERATION_FASTIO_CHECK_IF_POSSIBLE:
        case PROCMON_FILESYSTEM_OPERATION_IRP_MJ_12:
        case PROCMON_FILESYSTEM_OPERATION_IRP_MJ_11:
        case PROCMON_FILESYSTEM_OPERATION_IRP_MJ_10:
        case PROCMON_FILESYSTEM_OPERATION_IRP_MJ_9:
        case PROCMON_FILESYSTEM_OPERATION_IRP_MJ_8:
        case PROCMON_FILESYSTEM_OPERATION_FASTIO_NOTIFY_STREAM_FO_CREATION:
        case PROCMON_FILESYSTEM_OPERATION_FASTIO_RELEASE_FOR_CC_FLUSH:
        case PROCMON_FILESYSTEM_OPERATION_FASTIO_ACQUIRE_FOR_CC_FLUSH:
        case PROCMON_FILESYSTEM_OPERATION_FASTIO_RELEASE_FOR_MOD_WRITE:
        case PROCMON_FILESYSTEM_OPERATION_FASTIO_ACQUIRE_FOR_MOD_WRITE:
        case PROCMON_FILESYSTEM_OPERATION_FASTIO_RELEASE_FOR_SECTION_SYNCHRONIZATION:
        case PROCMON_FILESYSTEM_OPERATION_CREATE_FILE_MAPPING:
        case PROCMON_FILESYSTEM_OPERATION_CREATE_FILE:
        case PROCMON_FILESYSTEM_OPERATION_CREATE_PIPE:
        case PROCMON_FILESYSTEM_OPERATION_IRP_MJ_CLOSE:
        case PROCMON_FILESYSTEM_OPERATION_READ_FILE:
        case PROCMON_FILESYSTEM_OPERATION_WRITE_FILE:
        case PROCMON_FILESYSTEM_OPERATION_QUERY_INFORMATION_FILE:
        case PROCMON_FILESYSTEM_OPERATION_SET_INFORMATION_FILE:
        case PROCMON_FILESYSTEM_OPERATION_QUERY_EA_FILE:
        case PROCMON_FILESYSTEM_OPERATION_SET_EA_FILE:
        case PROCMON_FILESYSTEM_OPERATION_FLUSH_BUFFERS_FILE:
        case PROCMON_FILESYSTEM_OPERATION_QUERY_VOLUME_INFORMATION:
        case PROCMON_FILESYSTEM_OPERATION_SET_VOLUME_INFORMATION:
        case PROCMON_FILESYSTEM_OPERATION_DIRECTORY_CONTROL:
        case PROCMON_FILESYSTEM_OPERATION_FILE_SYSTEM_CONTROL:
        case PROCMON_FILESYSTEM_OPERATION_DEVICE_IO_CONTROL:
        case PROCMON_FILESYSTEM_OPERATION_INTERNAL_DEVICE_IO_CONTROL:
        case PROCMON_FILESYSTEM_OPERATION_SHUTDOWN:
        case PROCMON_FILESYSTEM_OPERATION_LOCK_UNLOCK_FILE:
        case PROCMON_FILESYSTEM_OPERATION_CLOSE_FILE:
        case PROCMON_FILESYSTEM_OPERATION_CREATE_MAIL_SLOT:
        case PROCMON_FILESYSTEM_OPERATION_QUERY_SECURITY_FILE:
        case PROCMON_FILESYSTEM_OPERATION_SET_SECURITY_FILE:
        case PROCMON_FILESYSTEM_OPERATION_POWER:
        case PROCMON_FILESYSTEM_OPERATION_SYSTEM_CONTROL:
        case PROCMON_FILESYSTEM_OPERATION_DEVICE_CHANGE:
        case PROCMON_FILESYSTEM_OPERATION_QUERY_FILE_QUOTA:
        case PROCMON_FILESYSTEM_OPERATION_SET_FILE_QUOTA:
        case PROCMON_FILESYSTEM_OPERATION_PLUG_AND_PLAY:
            break;
        default:
            break;
    }

    return offset;
}

#define PROCMON_PROFILING_OPERATION_THREAD       0x0000
#define PROCMON_PROFILING_OPERATION_PROCESS      0x0001
#define PROCMON_PROFILING_OPERATION_DEBUG_OUTPUT 0x0002

static const value_string profiling_operation_vals[] = {
        { PROCMON_PROFILING_OPERATION_THREAD,       "Thread" },
        { PROCMON_PROFILING_OPERATION_PROCESS,      "Process" },
        { PROCMON_PROFILING_OPERATION_DEBUG_OUTPUT, "Debug Output" },
        { 0, NULL }
};

static int dissect_procmon_profiling_event(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset, uint32_t size, int operation_offset)
{
    proto_tree* profiling_tree;
    proto_item* operation_ti;
    uint32_t operation;
    const char* operation_str;

    profiling_tree = proto_tree_add_subtree(tree, tvb, offset, size, ett_procmon_profiling_event, NULL, "Profiling Data");
    operation_ti = proto_tree_add_item_ret_uint(profiling_tree, hf_procmon_profiling_operation, tvb, operation_offset, 2, ENC_LITTLE_ENDIAN, &operation);

    operation_str = try_val_to_str(operation, profiling_operation_vals);
    if (operation_str == NULL)
    {
        expert_add_info_format(pinfo, operation_ti, &ei_procmon_unknown_operation, "Unknown profiling operation: 0x%04x", operation);
        col_add_fstr(pinfo->cinfo, COL_INFO, "Profiling Operation: Unknown (0x%04x)", operation);
    }
    else
    {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Profiling Operation: %s", operation_str);
    }

    switch(operation)
    {
        case PROCMON_PROFILING_OPERATION_THREAD:
        case PROCMON_PROFILING_OPERATION_PROCESS:
        case PROCMON_PROFILING_OPERATION_DEBUG_OUTPUT:
            //Unknown
            break;
        default:
            break;
    }

    return offset;
}

#define PROCMON_NETWORK_OPERATION_UNKNOWN       0x0000
#define PROCMON_NETWORK_OPERATION_OTHER         0x0001
#define PROCMON_NETWORK_OPERATION_SEND          0x0002
#define PROCMON_NETWORK_OPERATION_RECEIVE       0x0003
#define PROCMON_NETWORK_OPERATION_ACCEPT        0x0004
#define PROCMON_NETWORK_OPERATION_CONNECT       0x0005
#define PROCMON_NETWORK_OPERATION_DISCONNECT    0x0006
#define PROCMON_NETWORK_OPERATION_RECONNECT     0x0007
#define PROCMON_NETWORK_OPERATION_RETRANSMIT    0x0008
#define PROCMON_NETWORK_OPERATION_TCP_COPY      0x0009

static const value_string network_operation_vals[] = {
        { PROCMON_NETWORK_OPERATION_UNKNOWN,    "Unknown" },
        { PROCMON_NETWORK_OPERATION_OTHER,      "Other" },
        { PROCMON_NETWORK_OPERATION_SEND,       "Send" },
        { PROCMON_NETWORK_OPERATION_RECEIVE,    "Receive" },
        { PROCMON_NETWORK_OPERATION_ACCEPT,     "Accept" },
        { PROCMON_NETWORK_OPERATION_CONNECT,    "Connect" },
        { PROCMON_NETWORK_OPERATION_DISCONNECT, "Disconnect" },
        { PROCMON_NETWORK_OPERATION_RECONNECT,  "Reconnect" },
        { PROCMON_NETWORK_OPERATION_RETRANSMIT, "Retransmit" },
        { PROCMON_NETWORK_OPERATION_TCP_COPY,   "TCP Copy" },
        { 0, NULL }
};

static const true_false_string tfs_tcp_udp = { "TCP", "UDP" };

#define NETWORK_FLAG_IS_SRC_IPv4_MASK   0x0001
#define NETWORK_FLAG_IS_DEST_IPv4_MASK  0x0002
#define NETWORK_FLAG_IS_TCP_MASK        0x0004

static int dissect_procmon_network_event(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, uint32_t size, int operation_offset)
{
    proto_tree* network_event_tree;
    proto_item* operation_ti;
    uint32_t operation;
    const char* operation_str;
    uint16_t flags;
    int detail_length, detail_offset;
    uint8_t* detail_substring;
    wmem_strbuf_t* details = wmem_strbuf_new(pinfo->pool, "");
    static int* const network_flags_vals[] = {
            &hf_procmon_network_flags_is_src_ipv4,
            &hf_procmon_network_flags_is_dst_ipv4,
            &hf_procmon_network_flags_tcp_udp,
            NULL
    };

    network_event_tree = proto_tree_add_subtree(tree, tvb, offset, size, ett_procmon_network_event, NULL, "Network Data");
    operation_ti = proto_tree_add_item_ret_uint(network_event_tree, hf_procmon_network_operation, tvb, operation_offset, 2, ENC_LITTLE_ENDIAN, &operation);
    operation_str = try_val_to_str(operation, network_operation_vals);
    if (operation_str == NULL)
    {
        expert_add_info_format(pinfo, operation_ti, &ei_procmon_unknown_operation, "Unknown network operation: 0x%04x", operation);
        col_add_fstr(pinfo->cinfo, COL_INFO, "Network Operation: Unknown (0x%04x)", operation);
    }
    else
    {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Network Operation: %s", operation_str);
    }

    proto_tree_add_bitmask_with_flags(network_event_tree, tvb, offset, hf_procmon_network_flags, ett_procmon_network_flags, network_flags_vals, ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
    flags = tvb_get_letohs(tvb, offset);
    offset += 2;

    //Unknown fields
    offset += 2;

    proto_tree_add_item(network_event_tree, hf_procmon_network_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    if (flags & NETWORK_FLAG_IS_SRC_IPv4_MASK)
    {
        proto_tree_add_item(network_event_tree, hf_procmon_network_src_ipv4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(network_event_tree, hf_procmon_network_padding, tvb, offset, 12, ENC_NA);
        offset += 12;
    }
    else
    {
        proto_tree_add_item(network_event_tree, hf_procmon_network_src_ipv6, tvb, offset, IPv6_ADDR_SIZE, ENC_NA);
        offset += IPv6_ADDR_SIZE;
    }
    if (flags & NETWORK_FLAG_IS_DEST_IPv4_MASK)
    {
        proto_tree_add_item(network_event_tree, hf_procmon_network_dest_ipv4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(network_event_tree, hf_procmon_network_padding, tvb, offset, 12, ENC_NA);
        offset += 12;
    }
    else
    {
        proto_tree_add_item(network_event_tree, hf_procmon_network_dest_ipv6, tvb, offset, IPv6_ADDR_SIZE, ENC_NA);
        offset += IPv6_ADDR_SIZE;
    }
    proto_tree_add_item(network_event_tree, hf_procmon_network_src_port, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(network_event_tree, hf_procmon_network_dest_port, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    detail_offset = offset;
    while (((detail_substring = tvb_get_stringz_enc(pinfo->pool, tvb, offset, &detail_length, ENC_UTF_16 | ENC_LITTLE_ENDIAN)) != NULL) && (strlen(detail_substring) > 0))
    {
        wmem_strbuf_append_printf(details, " %s", detail_substring);
        offset += detail_length;
    }
    //Include the NULL string at the end of the list
    offset += 2;
    proto_tree_add_string(network_event_tree, hf_procmon_network_details, tvb, detail_offset, offset-detail_offset, wmem_strbuf_get_str(details));

    switch(operation)
    {
        case PROCMON_NETWORK_OPERATION_UNKNOWN:
        case PROCMON_NETWORK_OPERATION_OTHER:
        case PROCMON_NETWORK_OPERATION_SEND:
        case PROCMON_NETWORK_OPERATION_RECEIVE:
        case PROCMON_NETWORK_OPERATION_ACCEPT:
        case PROCMON_NETWORK_OPERATION_CONNECT:
        case PROCMON_NETWORK_OPERATION_DISCONNECT:
        case PROCMON_NETWORK_OPERATION_RECONNECT:
        case PROCMON_NETWORK_OPERATION_RETRANSMIT:
        case PROCMON_NETWORK_OPERATION_TCP_COPY:
            break;
        default:
            break;
    }

    return offset;
}

static int
dissect_procmon_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti, *ti_event;
    proto_tree *procmon_tree, *header_tree, *stack_trace_tree;
    int         offset = 0, operation_offset;
    int         size_of_pointer;
    uint32_t event_class;
    uint32_t stack_trace_size, details_size, extra_details_offset;
    nstime_t timestamp;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_str(pinfo->cinfo, COL_INFO, "MS Procmon Event");

    ti = proto_tree_add_item(tree, proto_procmon, tvb, 0, -1, ENC_NA);
    procmon_tree = proto_item_add_subtree(ti, ett_procmon);

    header_tree = proto_tree_add_subtree(procmon_tree, tvb, offset, 52, ett_procmon_header, NULL, "Event Header");

    proto_tree_add_item(header_tree, hf_procmon_process_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(header_tree, hf_procmon_thread_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    ti_event = proto_tree_add_item_ret_uint(header_tree, hf_procmon_event_class, tvb, offset, 4, ENC_LITTLE_ENDIAN, &event_class);
    offset += 4;
    operation_offset = offset;
    proto_tree_add_item(header_tree, hf_procmon_operation_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    //Next 6 bytes are unknown
    offset += 6;
    proto_tree_add_item(header_tree, hf_procmon_duration, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    filetime_to_nstime(&timestamp, tvb_get_letoh64(tvb, offset));
    proto_tree_add_time(header_tree, hf_procmon_timestamp, tvb, offset, 8, &timestamp);
    offset += 8;
    proto_tree_add_item(header_tree, hf_procmon_event_result, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(header_tree, hf_procmon_stack_trace_depth, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    //Next 2 bytes are unknown
    offset += 2;
    proto_tree_add_item_ret_uint(header_tree, hf_procmon_details_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &details_size);
    offset += 4;
    proto_tree_add_item_ret_uint(header_tree, hf_procmon_extra_details_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &extra_details_offset);
    offset += 4;

    //Stack trace size part of the record
    stack_trace_size = tvb_get_letohl(tvb, offset);
    offset += 4;
    if (stack_trace_size > 0)
    {
        stack_trace_tree = proto_tree_add_subtree(procmon_tree, tvb, offset, stack_trace_size, ett_procmon_stack_trace, NULL, "Stack Trace");
        if (pinfo->pseudo_header->procmon.system_bitness)
        {
            size_of_pointer = 8;
        }
        else
        {
            size_of_pointer = 4;
        }
        for (uint32_t i = 0; i < stack_trace_size; i += size_of_pointer)
        {
            proto_tree_add_item(stack_trace_tree, hf_procmon_stack_trace_address, tvb, offset, size_of_pointer, ENC_LITTLE_ENDIAN);
            offset += size_of_pointer;
        }
    }

    switch(event_class)
    {
        case PROCMON_EVENT_CLASS_TYPE_PROCESS:
            dissect_procmon_process_event(tvb, pinfo, procmon_tree, offset, details_size, operation_offset);
            break;
        case PROCMON_EVENT_CLASS_TYPE_REGISTRY:
            dissect_procmon_registry_event(tvb, pinfo, procmon_tree, offset, details_size, operation_offset);
            break;
        case PROCMON_EVENT_CLASS_TYPE_FILE_SYSTEM:
            dissect_procmon_filesystem_event(tvb, pinfo, procmon_tree, offset, details_size, operation_offset);
            break;
        case PROCMON_EVENT_CLASS_TYPE_PROFILING:
            dissect_procmon_profiling_event(tvb, pinfo, procmon_tree, offset, details_size, operation_offset);
            break;
        case PROCMON_EVENT_CLASS_TYPE_NETWORK:
            dissect_procmon_network_event(tvb, pinfo, procmon_tree, offset, details_size, operation_offset);
            break;
        default:
            expert_add_info(pinfo, ti_event, &ei_procmon_unknown_event_class);
            proto_tree_add_item(procmon_tree, hf_procmon_detail_data, tvb, offset, details_size, ENC_NA);
            break;
    }
    offset += details_size;

    if (extra_details_offset > 0)
    {
        uint16_t extra_details_size = tvb_get_letohs(tvb, offset);
        offset += 2;
        proto_tree_add_item(procmon_tree, hf_procmon_extra_detail_data, tvb, offset, extra_details_size, ENC_NA);
        offset += extra_details_size;
    }

    return offset;
}

/*
 * Register the protocol with Wireshark.
 */
void
proto_register_procmon(void)
{
    static hf_register_info hf[] = {
        { &hf_procmon_process_index,
          { "Process Index", "procmon.process_index",
            FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_thread_id,
          { "Thread ID", "procmon.thread_id",
            FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_event_class,
          { "Event Class", "procmon.event_class",
            FT_UINT32, BASE_DEC, VALS(event_class_vals), 0, NULL, HFILL}
        },
        { &hf_procmon_operation_type,
          { "Operation Type", "procmon.operation_type",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_duration,
          { "Duration", "procmon.duration",
            FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_timestamp,
          { "Timestamp", "procmon.timestamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_event_result,
          { "Event Result", "procmon.event_result",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_stack_trace_depth,
          { "Stack Trace Depth", "procmon.stack_trace_depth",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_details_size,
          { "Details Size", "procmon.details_size",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_extra_details_offset,
          { "Extra Details Offset", "procmon.extra_details_offset",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_stack_trace_address,
          { "Stack trace address", "procmon.stack_trace_address",
            FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_detail_data,
          { "Detail Data", "procmon.detail_data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_extra_detail_data,
          { "Extra detail data", "procmon.extra_detail_data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_operation,
          { "Operation Type", "procmon.process.operation_type",
            FT_UINT16, BASE_DEC, VALS(process_operation_vals), 0, NULL, HFILL}
        },
        { &hf_procmon_process_pid,
          { "PID", "procmon.process.pid",
            FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_path,
          { "Path", "procmon.process.path",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_path_size,
          { "Path Size", "procmon.process.path.size",
            FT_UINT16, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_path_is_ascii,
          { "Is ASCII", "procmon.process.path.is_ascii",
            FT_BOOLEAN, 16, NULL, STRING_IS_ASCII_MASK, NULL, HFILL }
        },
        { &hf_procmon_process_path_char_count,
          { "Char Count", "procmon.process.path.char_count",
            FT_UINT16, BASE_DEC, NULL, STRING_CHAR_COUNT_MASK, NULL, HFILL }
        },
        { &hf_procmon_process_commandline,
          { "Commandline", "procmon.process.commandline",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_commandline_size,
          { "Commandline Size", "procmon.process.commandline.size",
            FT_UINT16, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_commandline_is_ascii,
          { "Is ASCII", "procmon.process.commandline.is_ascii",
            FT_BOOLEAN, 16, NULL, STRING_IS_ASCII_MASK, NULL, HFILL }
        },
        { &hf_procmon_process_commandline_char_count,
          { "Char Count", "procmon.process.commandline.char_count",
            FT_UINT16, BASE_DEC, NULL, STRING_CHAR_COUNT_MASK, NULL, HFILL }
        },
        { &hf_procmon_process_exit_status,
          { "Exit Status", "procmon.process.exit_status",
            FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_kernel_time,
          { "Kernel time", "procmon.process.kernel_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_user_time,
          { "User time", "procmon.process.user_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_working_set,
          { "Working Set", "procmon.process.working_set",
            FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_peak_working_set,
          { "Peak Working Set", "procmon.process.peak_working_set",
            FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_private_bytes,
          { "Private Bytes", "procmon.process.private_bytes",
            FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_peak_private_bytes,
          { "Peak Private Bytes", "procmon.process.peak_private_bytes",
            FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_thread_id,
          { "Thread ID", "procmon.process.thread_id",
            FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_image_base,
          { "Image Base", "procmon.process.image_base",
            FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_image_size,
          { "Image Size", "procmon.process.image_size",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_parent_pid,
          { "Parent PID", "procmon.process.parent_pid",
            FT_UINT32, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_curdir,
          { "Current Directory", "procmon.process.curdir",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_curdir_size,
          { "Current Directory Size", "procmon.process.curdir.size",
            FT_UINT16, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_curdir_is_ascii,
          { "Is ASCII", "procmon.process.curdir.is_ascii",
            FT_BOOLEAN, 16, NULL, STRING_IS_ASCII_MASK, NULL, HFILL }
        },
        { &hf_procmon_process_curdir_char_count,
          { "Char Count", "procmon.process.curdir.char_count",
            FT_UINT16, BASE_DEC, NULL, STRING_CHAR_COUNT_MASK, NULL, HFILL }
        },
        { &hf_procmon_process_environment_char_count,
          { "Environment Size", "procmon.process.environment.char_count",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_process_environment,
          { "Environment", "procmon.process.environment",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_operation,
          { "Operation Type", "procmon.registry.operation_type",
            FT_UINT16, BASE_DEC, VALS(registry_operation_vals), 0, NULL, HFILL }
        },
        { &hf_procmon_registry_desired_access,
          { "Desired Access", "procmon.registry.desired_access",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_key,
          { "Key", "procmon.registry.key",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_key_size,
          { "Key Size", "procmon.registry.key.size",
            FT_UINT16, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_key_is_ascii,
          { "Is ASCII", "procmon.registry.key.is_ascii",
            FT_BOOLEAN, 16, NULL, STRING_IS_ASCII_MASK, NULL, HFILL }
        },
        { &hf_procmon_registry_key_char_count,
          { "Char Count", "procmon.registry.key.char_count",
            FT_UINT16, BASE_DEC, NULL, STRING_CHAR_COUNT_MASK, NULL, HFILL }
        },
        { &hf_procmon_registry_new_key,
          { "New Key", "procmon.registry.new_key",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_new_key_size,
          { "New Key Size", "procmon.registry.new_key.size",
            FT_UINT16, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_new_key_is_ascii,
          { "Is ASCII", "procmon.registry.new_key.is_ascii",
            FT_BOOLEAN, 16, NULL, STRING_IS_ASCII_MASK, NULL, HFILL }
        },
        { &hf_procmon_registry_new_key_char_count,
          { "Char Count", "procmon.registry.new_key.char_count",
            FT_UINT16, BASE_DEC, NULL, STRING_CHAR_COUNT_MASK, NULL, HFILL }
        },
        { &hf_procmon_registry_value,
          { "Value", "procmon.registry.value",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_value_size,
          { "Value Size", "procmon.registry.value.size",
            FT_UINT16, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_value_is_ascii,
          { "Is ASCII", "procmon.registry.value.is_ascii",
            FT_BOOLEAN, 16, NULL, STRING_IS_ASCII_MASK, NULL, HFILL }
        },
        { &hf_procmon_registry_value_char_count,
          { "Char Count", "procmon.registry.value.char_count",
            FT_UINT16, BASE_DEC, NULL, STRING_CHAR_COUNT_MASK, NULL, HFILL }
        },
        { &hf_procmon_registry_length,
          { "Length", "procmon.registry.length",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_information_class,
          { "Information Class", "procmon.registry.information_class",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_index,
          { "Index", "procmon.registry.index",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_type,
          { "Type", "procmon.registry.type",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_data_length,
          { "Data Length", "procmon.registry.data_length",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_registry_key_information_class,
          { "Key Information Class", "procmon.registry.key_information_class",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_operation,
          { "Operation Type", "procmon.filesystem.operation_type",
            FT_UINT16, BASE_DEC, VALS(filesystem_operation_vals), 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_suboperation,
          { "Suboperation", "procmon.filesystem.suboperation",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_padding,
          { "Padding", "procmon.filesystem.padding",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_details,
          { "Details", "procmon.filesystem.details",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_path,
          { "Value", "procmon.filesystem.path",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_path_size,
          { "Value Size", "procmon.filesystem.path.size",
            FT_UINT16, BASE_DEC_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_filesystem_path_is_ascii,
          { "Is ASCII", "procmon.filesystem.path.is_ascii",
            FT_BOOLEAN, 16, NULL, STRING_IS_ASCII_MASK, NULL, HFILL }
        },
        { &hf_procmon_filesystem_path_char_count,
          { "Char Count", "procmon.filesystem.path.char_count",
            FT_UINT16, BASE_DEC, NULL, STRING_CHAR_COUNT_MASK, NULL, HFILL }
        },
        { &hf_procmon_profiling_operation,
          { "Operation Type", "procmon.profiling.operation_type",
            FT_UINT16, BASE_DEC, VALS(profiling_operation_vals), 0, NULL, HFILL }
        },
        { &hf_procmon_network_operation,
          { "Operation Type", "procmon.network.operation_type",
            FT_UINT16, BASE_DEC, VALS(network_operation_vals), 0, NULL, HFILL }
        },
        { &hf_procmon_network_flags,
          { "Flags", "procmon.network.flags",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_network_flags_is_src_ipv4,
          { "Is Src IPv4", "procmon.network.flags.is_src_ipv4",
            FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL }
        },
        { &hf_procmon_network_flags_is_dst_ipv4,
          { "Is Dest IPv4", "procmon.network.flags.is_dst_ipv4",
            FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL }
        },
        { &hf_procmon_network_flags_tcp_udp,
          { "TCP/UDP", "procmon.network.flags.tcp_udp",
            FT_BOOLEAN, 16, TFS(&tfs_tcp_udp), 0x0004, NULL, HFILL}
        },
        { &hf_procmon_network_length,
          { "Length", "procmon.network.length",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_network_src_ipv4,
          { "Src IP", "procmon.network.src_ipv4",
            FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_network_src_ipv6,
          { "Src IP", "procmon.network.src_ipv6",
            FT_IPv6, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_network_dest_ipv4,
          { "Dest IP", "procmon.network.dest_ipv4",
            FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_network_dest_ipv6,
          { "Dest IP", "procmon.network.dest_ipv6",
            FT_IPv6, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_network_src_port,
          { "Src Port", "procmon.network.src_port",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_network_dest_port,
          { "Dest Port", "procmon.network.dest_port",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_network_padding,
          { "Padding", "procmon.network.padding",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_procmon_network_details,
          { "Details", "procmon.network.details",
            FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL }
        },

    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_procmon,
        &ett_procmon_header,
        &ett_procmon_stack_trace,
        &ett_procmon_process_event,
        &ett_procmon_process_path,
        &ett_procmon_process_commandline,
        &ett_procmon_process_curdir,
        &ett_procmon_registry_event,
        &ett_procmon_registry_key,
        &ett_procmon_registry_new_key,
        &ett_procmon_registry_value,
        &ett_procmon_filesystem_event,
        &ett_procmon_filesystem_path,
        &ett_procmon_profiling_event,
        &ett_procmon_network_event,
        &ett_procmon_network_flags,
    };

    static ei_register_info ei[] = {
            { &ei_procmon_unknown_event_class, { "procmon.event_class.unknown", PI_UNDECODED, PI_WARN, "Unknown event class", EXPFILL }},
            { &ei_procmon_unknown_operation, { "procmon.operation_type.unknown", PI_UNDECODED, PI_WARN, "Unknown event class", EXPFILL }},
    };

    expert_module_t* expert_procmon;

    /* Register the protocol name and description */
    proto_procmon = proto_register_protocol(PNAME, PSNAME, PFNAME);

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_procmon, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_procmon = expert_register_protocol(proto_procmon);
    expert_register_field_array(expert_procmon, ei, array_length(ei));

    procmon_handle = register_dissector("procmon", dissect_procmon_event, proto_procmon);
}

void
proto_reg_handoff_procmon(void)
{
    int file_type_subtype_procmon;

    file_type_subtype_procmon = wtap_name_to_file_type_subtype("procmon");
    if (file_type_subtype_procmon != -1)
        dissector_add_uint("wtap_fts_rec", file_type_subtype_procmon, procmon_handle);
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
