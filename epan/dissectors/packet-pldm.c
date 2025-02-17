/* packet-pldm.c
 * Routines for Platform Level Data Model(PLDM) packet
 * disassembly
 * https://www.dmtf.org/sites/default/files/standards/documents/DSP0240_1.1.0.pdf
 * https://www.dmtf.org/sites/default/files/standards/documents/DSP0248_1.2.0.pdf
 * https://www.dmtf.org/sites/default/files/standards/documents/DSP0257_1.0.1_0.pdf
 * https://www.dmtf.org/sites/default/files/standards/documents/DSP0247_1.0.0.pdf
 * 
 * 
 * Copyright 2023, Riya Dixit <riyadixitagra@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"
#include <epan/packet.h>
#include <wsutil/wmem/wmem.h>
#include <wsutil/wmem/wmem_strbuf.h>

#define PLDM_MIN_LENGTH 4
#define PLDM_MAX_TYPES 8
/*BIOS*/                  
#define BCD44_TO_DEC(x) ((((x)&0xf0) >> 4) * 10 + ((x)&0x0f))

static int proto_pldm;
static int ett_pldm;

static wmem_map_t* pldmTypeMap;
static wmem_allocator_t *addr_resolv_scope;

static int hf_pldm_msg_direction;
static int hf_pldm_instance_id;
static int hf_pldm_header_version;
static int hf_pldm_type;
static int hf_pldm_reserved;
static int hf_pldm_base_commands;
static int hf_pldm_BIOS_commands;
static int hf_pldm_FRU_commands;
static int hf_pldm_platform_commands;
static int hf_pldm_base_typeVersion;
static int hf_pldm_base_PLDMtype;
static int hf_pldm_base_typesSupported;
static int hf_pldm_base_transferOperationFlag;
static int hf_pldm_base_nextDataTransferHandle;
static int hf_pldm_base_transferFlag;
static int hf_pldm_base_dataTransferHandle;
static int hf_pldm_base_TID;
static int hf_pldm_completion_code;

/*platform*/

static int hf_pldm_platform_completion_code;
/* Set Event Receiver */
static int hf_event_message_global;
static int hf_transport_protocol_type;
static int hf_event_receiver_addr_info;
static int hf_heartbeat_timer;

/* Event messages */
static int hf_pldm_platform_format_version;
static int hf_event_class;
static int hf_sensor_id;
static int hf_sensor_event_class;
static int hf_sensor_offset;
static int hf_event_state;
static int hf_event_prev_state;
static int hf_sensor_data_size;
static int hf_sensor_value_u8;
static int hf_sensor_value_s8;
static int hf_sensor_value_u16;
static int hf_sensor_value_s16;
static int hf_sensor_value_u32;
static int hf_sensor_value_s32;
static int hf_sensor_present_op_state;
static int hf_sensor_prev_op_state;
static int hf_heartbeat_format_ver;
static int hf_heartbeat_sequence_num;
static int hf_pdr_data_format;
static int hf_pdr_num_change_recs;
static int hf_pdr_repo_change_event_data_op;
static int hf_pdr_repo_change_rec_num_change_entries;
static int hf_pdr_repo_change_event_record_pdr_type;
static int hf_pdr_repo_change_event_record_pdr_record_handle;
static int hf_result_status;

/* GetStateSensorReadings */
static int hf_sensor_rearm;
static int hf_sensor_composite_count;
static int hf_sensor_event_state;
static int hf_sensor_present_event_state;
static int hf_sensor_prev_event_state;
static int hf_pldm_sensor_reserved;
static int hf_sensor_rearm_none;

/* GetSensorReading */
static int hf_event_rearm;
static int hf_sensor_event_msg_enable;

/* SetNumericEffecterValue */
static int hf_effecter_id;
static int hf_effecter_count;
static int hf_effecter_datasize;
static int hf_effecter_value_u8;
static int hf_effecter_value_s8;
static int hf_effecter_value_u16;
static int hf_effecter_value_s16;
static int hf_effecter_value_u32;
static int hf_effecter_value_s32;

/* GetNumericEffecterValue */
static int hf_effecter_op_state;
static int hf_effecter_value_pnd_u8;
static int hf_effecter_value_pnd_s8;
static int hf_effecter_value_pnd_u16;
static int hf_effecter_value_pnd_s16;
static int hf_effecter_value_pnd_u32;
static int hf_effecter_value_pnd_s32;
static int hf_effecter_value_pres_u8;
static int hf_effecter_value_pres_s8;
static int hf_effecter_value_pres_u16;
static int hf_effecter_value_pres_s16;
static int hf_effecter_value_pres_u32;
static int hf_effecter_value_pres_s32;

/* SetStateEffecterStates */
static int hf_effecter_set_request;
static int hf_effecter_state;

/* GetPDR */
static int hf_pdr_record_handle;
static int hf_pdr_data_handle;
static int hf_pdr_transfer_op_flag;
static int hf_pdr_req_count;
static int hf_pdr_record_change_num;
static int hf_pdr_next_record_handle;
static int hf_pdr_next_data_handle;
static int hf_pdr_transfer_flag;
static int hf_pdr_response_count;
static int hf_transfer_crc;
static int hf_pdr_record_data;

/* FRU definitions */
/* FRU specific completion code */
static int hf_fru_completion_code;
static int hf_fru_major_ver;
static int hf_fru_minor_ver;
static int hf_fru_table_max_size;
static int hf_fru_table_length;
static int hf_fru_num_record_identifiers;
static int hf_fru_num_records;
static int hf_fru_table_crc;

static int hf_fru_data_handle;
static int hf_fru_transfer_op_flag;
static int hf_fru_next_data_handle;
static int hf_fru_transfer_flag;

// FRU Record fields
static int hf_fru_record_id;
static int hf_fru_record_type;
static int hf_fru_record_num_fields;
static int hf_fru_record_encoding;
static int hf_fru_record_field_type;
static int hf_fru_record_field_len;
static int hf_fru_record_field_value;
static int hf_fru_record_crc;
static int hf_fru_table_handle;

/*BIOS*/
static int hf_bios_attr_handle;
static int hf_bios_attr_type;
static int hf_bios_attr_name_handle;
static int hf_bios_enumer_num_pos_values;
static int hf_bios_enumer_pos_value_str_hndl;
static int hf_bios_enumer_num_default_values;
static int hf_bios_enumer_default_value_str_hndl;
static int hf_bios_attr_table_pad_bytes;
static int hf_bios_attr_table_checksum;
static int hf_bios_str_handle;
static int hf_bios_str_len;
static int hf_bios_str;
static int hf_bios_string_type;
static int hf_bios_min_str_len;
static int hf_bios_max_str_len;
static int hf_bios_def_str_len;
static int hf_bios_def_str;
static int hf_bios_int_lower_bound;
static int hf_bios_int_upper_bound;
static int hf_bios_int_scalar_inc;
static int hf_bios_int_def_val;
static int hf_bios_boot_config_type;
static int hf_bios_fail_through_modes;
static int hf_bios_min_num_boot_src;
static int hf_bios_max_num_boot_src;
static int hf_bios_pos_num_boot_src;
static int hf_bios_src_str_hndl;
static int hf_bios_col_name_str_hndl;
static int hf_bios_max_num_attr;
static int hf_bios_col_type;
static int hf_bios_num_pos_config;
static int hf_bios_pos_config_str_hndl;
static int hf_bios_enumer_num_cur_values;
static int hf_bios_enumer_cur_value_str_hndl;
static int hf_bios_cur_str_len;
static int hf_bios_cur_str;
static int hf_bios_cur_pass_len;
static int hf_bios_cur_pass;
static int hf_bios_cur_val;
static int hf_bios_num_boot_src;
static int hf_bios_boot_src_str_hndl;
static int hf_bios_num_attr;
static int hf_bios_attr_hndl;
static int hf_bios_cur_config_set_str_hndl;
static int hf_bios_enumer_num_pen_values;
static int hf_bios_enumer_pen_value_str_hndl;
static int hf_bios_pen_str_len;
static int hf_bios_pen_str;
static int hf_bios_pen_pass_len;
static int hf_bios_pen_pass;
static int hf_bios_pen_val;
static int hf_bios_config_set_str_hndl;
static int hf_bios_pass_type;
static int hf_bios_min_pass_len;
static int hf_bios_max_pass_len;
static int hf_bios_def_pass_len;
static int hf_bios_def_pass;
static int hf_bios_num_pen_boot_src;
static int hf_bios_table_type;
static int hf_bios_next_data_handle;
static int hf_bios_transfer_flag;
static int hf_bios_enum_curr_str_hndl_idx;
static int hf_bios_data_handle;
static int hf_bios_num_curr_value;

// Date and Time
static int hf_pldm_time;
static int hf_pldm_date;

static const value_string directions[] = {
	{0, "response"},
	{1, "reserved"},
	{2, "request"},
	{3, "async/unack"},
	{0, NULL}
};

static const value_string pldm_types[] = {
	{0, "PLDM Messaging and Discovery"},
	{1, "PLDM for SMBIOS"},
	{2, "PLDM Platform Monitoring and Control"},
	{3, "PLDM for BIOS Control and Configuration"},
	{4, "PLDM for FRU Data"},
	{5, "PLDM for Firmware Update"},
	{6, "PLDM for Redfish Device Enablement"},
	{63, "OEM Specific"},
	{0, NULL}
};

static const value_string pldmBaseCmd[] = {
	{1, "Set TID"},
	{2, "Get TID"},
	{3, "Get PLDM Version"},
	{4, "Get PLDM Types"},
	{5, "GetPLDMCommands"},
	{6, "SelectPLDMVersion"},
	{7, "NegotiateTransferParameters"},
	{8, "Multipart Send"},
	{9, "Multipart Receive"},
	{0, NULL}
};

static const value_string pldmPlatformCmds[] = {
	{4, "SetEventReceiver"},
	{10, "PlatformEventMessage"},
	{17, "GetSensorReading"},
	{33, "GetStateSensorReadings"},
	{49, "SetNumericEffecterValue"},
	{50, "GetNumericEffecterValue"},
	{57, "SetStateEffecterStates"},
	{81, "GetPDR"},
	{0, NULL}
};

static const value_string pldmFruCmds[] = {
	{1, "GetFRURecordTableMetadata"},
	{2, "GetFRURecordTable"},
	{3, "SetFRURecordTable"},
	{4, "GetFRURecordByOption"},
	{0, NULL}
};

static const value_string pldmBIOScmd[] = {
	{1, "GetBIOSTable"},
	{2, "SetBIOSTable"},
	{7, "SetBIOSAttributeCurrentValue"},
	{8, "GetBIOSAttributeCurrentValueByHandle"},
	{12, "GetDateTime"},
	{13, "SetDateTime"},
	{0, NULL}
};

static const value_string transferOperationFlags[] = {
	{0, "GetNextPart"},
	{1, "GetFirstPart"},
	{0, NULL}
};

static const value_string transferFlags[] = {
	{1, "Start"},
	{2, "Middle"},
	{4, "End"},
	{5, "StartAndEnd"},
	{0, NULL}
};

static const value_string completion_codes[] = {
	{0x0, "Success"},
	{0x1, "Error"},
	{0x2, "Invalid Data"},
	{0x3, "Invalid Length"},
	{0x4, "Not Ready"},
	{0x5, "Unsupported PLDM command"},
	{0x20, "Invalid PLDM type"},
	{0, NULL}
};

static const value_string platform_completion_codes[] = {
	{0x0, "Success"},
	{0x1, "Error"},
	{0x2, "Invalid Data"},
	{0x3, "Invalid Length"},
	{0x4, "Not Ready"},
	{0x5, "Unsupported PLDM command"},
	{0x20, "Invalid PLDM type"},
	{0x80, "PLDM Platform Invalid ID/Data Handle/Protocol Type"},
	{0x81, "Unsupported Event Format Version"},
	{0x82, "PLDM Platform Invalid Record Handle"},
	{0x83, "PLDM Platform Invalid Record Change Number"},
	{0x84, "PLDM Platform PDR Transfer Timeout"},
	{0x85, "Repository update in progress"},
	{0, NULL}
};


/* platform */

static const value_string event_message_global_enable[] = {
	{0, "Disable"},
	{1, "Enable Async"},
	{2, "Enable Polling"},
	{3, "Enable Async Keep Alive"},
	{0, NULL}
};

static const value_string transport_protocols[] = {
	{0, "MCTP"},
	{1, "NC-SI/RBT"},
	{2, "Vendor Specific"},
	{0, NULL}
};

static const value_string platform_event_message_classes[] = {
	{0, "Sensor Event"},
	{1, "Effecter Event"},
	{2, "Redfish Task Event"},
	{3, "Redfish Message Event"},
	{4, "Pldm PDR Repository Change Event"},
	{5, "Pldm Message Poll Event"},
	{6, "Heartbeat Timer Elapsed Event"},
	{0, NULL}
};

static const value_string sensor_data_size[] = {
	{0, "uint8"},
	{1, "sint8"},
	{2, "uint16"},
	{3, "sint16"},
	{4, "uint32"},
	{5, "sint32"},
	{0, NULL}
};

static const value_string pldm_pdr_repository_chg_event_data_format[] = {
	{0, "Refresh Entire Repository"},
	{1, "Format is PDR Types"},
	{2, "Format is PDR Handles"},
	{0, NULL}
};

static const value_string sensor_platform_event_message_classes[] = {
	{0, "Sensor Operational"},
	{1, "State Sensor State"},
	{2, "Numeric Sensor State"},
	{0, NULL}
};

static const value_string platform_sensor_operational_state[] = {
	{0, "PLDM Sensor Enabled"},
	{1, "PLDM Sensor Disabled"},
	{2, "PLDM Sensor Unavailable"},
	{3, "PLDM Sensor Status Unknown"},
	{4, "PLDM Sensor Failed"},
	{5, "PLDM Sensor Initializing"},
	{6, "PLDM Sensor SHUTTING DOWN"},
	{7, "PLDM Sensor Intest"},
	{0, NULL}
};

static const value_string pdr_repo_chg_event_data_operation[] = {
	{0, "PLDM Refresh all Records"},
	{1, "PLDM Records Deleted"},
	{2, "PLDM Records Added"},
	{3, "PLDM Records Modified"},
	{0, NULL}
};

static const value_string platform_pdr_type[] = {
	{1, "PLDM Terminus Locator PDR"},
	{2, "PLDM Numeric Sensor PDR"},
	{3, "PLDM Numeric Sensor Initialization PDR"},
	{4, "PLDM State Sensor PDR"},
	{5, "PLDM State Sensor Initialization PDR"},
	{6, "PLDM Sensor Auxiliary Names PDR"},
	{7, "PLDM OEM Unit PDR"},
	{8, "PLDM OEM State Set PDR"},
	{9, "PLDM Numeric Effecter PDR"},
	{10, "PLDM Numeric Effecter Initialization PDR"},
	{11, "PLDM State Effecter PDR"},
	{12, "PLDM State Effecter Initialization PDR"},
	{13, "PLDM Effecter Auxiliary Names PDR"},
	{14, "PLDM Effecter OEM Semantic PDR"},
	{15, "PLDM PDR Entity Association"},
	{16, "PLDM Entity Auxiliary Names PDR"},
	{17, "PLDM OEM Entity ID PDR"},
	{18, "PLDM Interrupt Association PDR"},
	{19, "PLDM Event Log PDR"},
	{20, "PLDM PDR FRU Record Set"},
	{21, "PLDM Compact Numeric Sensor PDR"},
	{126, "PLDM OEM Device PDR"},
	{127, "PLDM OEM PDR"},
	{0, NULL}
};

static const value_string pldm_sensor_event_states[] = {
	{0, "PLDM Sensor Unknown"},
	{1, "PLDM Sensor Normal"},
	{2, "PLDM Sensor Warning"},
	{3, "PLDM Sensor Critical"},
	{4, "PLDM Sensor Fatal"},
	{5, "PLDM Sensor Lower Warning"},
	{6, "PLDM Sensor Lower Critical"},
	{7, "PLDM Sensor Lower Fatal"},
	{8, "PLDM Sensor Upper Warning"},
	{9, "PLDM Sensor Upper Critical"},
	{10, "PLDM Sensor Upper fatal"},
	{0, NULL}
};

static const value_string pldm_sensor_event_message_enable[] = {
	{0, "PLDM NO Event Generation"},
	{1, "PLDM Events Disabled"},
	{2, "PLDM Events Enabled"},
	{3, "PLDM Operation Events Only Enabled"},
	{4, "PLDM State Events Only Enabled"},
	{0, NULL}
};

static const value_string pldm_effecter_oper_state[] = {
	{0, "Effecter Operational State Enabled Update Pending"},
	{1, "Effecter Operational State Enabled No Update Pending"},
	{2, "Effecter Operational State Disabled"},
	{3, "Effecter Operational State Unavailable"},
	{4, "Effecter Operational State Status Unknown"},
	{5, "Effecter Operational State Failed"},
	{6, "Effecter Operational State Initializing"},
	{7, "Effecter Operational State Shutting Down"},
	{8, "Effecter Operational State Intest"},
	{0, NULL}
};

static const value_string transfer_op_flags[] = {
	{0, "Get Next Part"},
	{1, "Get First Part"},
	{0, NULL}
};

static const value_string pldm_effecter_state_set_request[] = {
	{0, "No Change"},
	{1, "Request Set"},
	{0, NULL}
};

static const value_string pdr_transfer_flags[] = {
	{0, "Start"},
	{1, "Middle"},
	{4, "End"},
	{5, "Start and End"},
	{0, NULL}
};

static const value_string sensor_bool8[] = {
	{0x01, "True"},
	{0x00, "False"},
	{0, NULL}
};

static const value_string result_status[] = {
	{0, "No Logging"},
	{1, "Logging Disabled"},
	{2, "Log Full"},
	{3, "Accepted for Logging"},
	{4, "Logged"},
	{5, "Logging Rejected"},
	{0, NULL}
};

/* FRU */
static const value_string FRU_completion_code[] = {
	{0x80, "Invalid data transfer handle"},
	{0x81, "Invalid transfer operation flag"},
	{0x82, "Invalid transfer flag"},
	{0x83, "No FRU table metadata"},
	{0x84, "Invalid data integrity check"},
	{0x85, "Fru data table unavailable"},
	{0, NULL}
};

static const value_string record_encoding[] = {
	{1, "ASCII"},
	{2, "UTF8"},
	{3, "UTF16"},
	{4, "UTF16-LE"},
	{5, "UTF16-BE"},
	{0, NULL}
};

static const value_string record_types[] = {
	{1, "General FRU Record"},
	{254, "OEM FRU Record"},
	{0, NULL}
};

static const value_string field_types_general[] = {
	{0x0, "Reserved"},
	{0x1, "Chassis Type"},
	{0x2, "Model"},
	{0x3, "Part Number"},
	{0x4, "Serial Number"},
	{0x5, "Manufacturer"},
	{0x6, "Manufacture Date"},
	{0x7, "Vendor"},
	{0x8, "Name"},
	{0x9, "SKU"},
	{0xa, "Version"},
	{0xb, "Asset Tag"},
	{0xc, "Description"},
	{0xd, "Engineering Change Level"},
	{0xe, "Other Information"},
	{0xf, "Vendor IANA"},
	{0, NULL}
};

/*BIOS*/
static const value_string bios_table_types[] = {
    {0x0, "BIOS String Table"},
    {0x1, "BIOS Attribute Table"},
    {0x2, "BIOS Attribute Value Table"},
    {0x3, "BIOS Attribute Pending Value Table"},
    {0, NULL}
};

static const value_string bios_attribute_type[] = {
    {0x0, "BIOSEnumeration"},
    {0x1, "BIOSString"},
    {0x2, "BIOSPassword"},
    {0x3, "BIOSInteger"},
    {0x4, "BIOSBootConfigSetting"},
    {0x5, "BIOSCollection"},
    {0x6, "BIOSConfigSet"},
    {0x80, "BIOSEnumerationReadOnly"},
    {0x81, "BIOSStringRaedOnly"},
    {0x82, "BIOSPasswordReadOnly"},
    {0x83, "BIOSIntegerReadOnly"},
    {0x84, "BIOSPasswordReadOnly"},
    {0x85, "BIOSCollectionReadOnly"},
    {0x86, "BIOSConfigSetReadOnly"},
	{0, NULL}
};

static const value_string pldm_bios_boot_config_type[]={                       
  {0x00, "Unknown"},
  {0x01, "Default"},
  {0x02, "Next"},
  {0x03, "Default and Next"},
  {0x04, "One Time"}, 
  {0x05, "Default and One Time"},
  {0, NULL}
};

static const value_string pldm_bios_fail_through_mode[]={
  {0x00, "Unordered and Limited Fail Through"},
  {0x01, "Unordered and Fail Through"},
  {0x02, "Ordered and Limited Fail Through"},
  {0x03, "Ordered and Fail Through"},
  {0, NULL}
};

/* Some details of frame seen passed info functions handling packet types.
   Not stored as per-packet data in frame...  */
typedef struct pldm_packet_data {
	uint8_t direction;
	uint8_t instance_id;
} pldm_packet_data;


/* Return number of characters written */
static void print_version_field(uint8_t bcd, wmem_strbuf_t *buf)
{
	int v;
	if (bcd == 0xff)
		// No value to write
		return;
	if ((bcd & 0xf0) == 0xf0) {
		// First nibble all set, so get value from 2nd nibble - show as bcd
		v = bcd & 0x0f;
		wmem_strbuf_append_printf(buf, "%d", v);
	} else {
		// Get one char from each nibble by printing as 2-digit number
		int tens = (bcd >> 4) & 0x0f;  // Extract the tens digit
		int units = bcd & 0x0f;        // Extract the units digit
		wmem_strbuf_append_printf(buf, "%d%d", tens, units);
	}
}

static const char* ver2str(tvbuff_t *tvb, int offset, packet_info *pinfo)
{
	uint8_t major = tvb_get_uint8(tvb, offset);
	uint8_t minor = tvb_get_uint8(tvb, offset+1);
	uint8_t update = tvb_get_uint8(tvb, offset+2);
	uint8_t alpha = tvb_get_uint8(tvb, offset+3);

	// major, minor and update fields are all BCD encoded
	wmem_strbuf_t *version_buf = wmem_strbuf_new(pinfo->pool, NULL);

	// Major
	if (major != 0xff) {
		print_version_field(major, version_buf);
		wmem_strbuf_append(version_buf, ".");
	} else {
		wmem_strbuf_append(version_buf, "-");
	}
	// Minor
	if (minor != 0xff) {
		print_version_field(minor, version_buf);
	} else {
		wmem_strbuf_append(version_buf, "-");
	}
	// Update
	if (update != 0xff) {
		wmem_strbuf_append(version_buf, ".");
		print_version_field(update, version_buf);
	} else {
		wmem_strbuf_append(version_buf, "-");
	}
	// Alpha
	if (alpha != 0x00) {
		wmem_strbuf_append_printf(version_buf, "%c", alpha);
	} else {
		wmem_strbuf_append(version_buf, "-");
	}

	return wmem_strbuf_finalize(version_buf);
}

static
int dissect_base(tvbuff_t *tvb, packet_info *pinfo, proto_tree *p_tree, const pldm_packet_data *data)
{
	static uint8_t pldmT = -1;
	uint8_t instID = data->instance_id;
	uint8_t request = data->direction;
	int    offset = 0;
	uint32_t pldm_cmd, completion_code;
	proto_tree_add_item_ret_uint(p_tree, hf_pldm_base_commands, tvb, offset, 1, ENC_LITTLE_ENDIAN, &pldm_cmd);
	offset += 1;
	if (!request) { //completion code in response only
		proto_tree_add_item_ret_uint(p_tree, hf_pldm_completion_code, tvb, offset, 1, ENC_LITTLE_ENDIAN, &completion_code);
		if (completion_code)
			return tvb_captured_length(tvb);
		offset += 1;
	}
	switch (pldm_cmd) {
		case 01: // SetTID
			if (request) {
				proto_tree_add_item(p_tree, hf_pldm_base_TID, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			}
			break;
		case 02: // GetTID
			if (!request) {
				proto_tree_add_item(p_tree, hf_pldm_base_TID, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			}
			break;
		case 03: // GetPLDMVersion
			if (request) {
				proto_tree_add_item(p_tree, hf_pldm_base_dataTransferHandle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				proto_tree_add_item(p_tree, hf_pldm_base_transferOperationFlag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;
				proto_tree_add_item(p_tree, hf_pldm_base_PLDMtype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			} else {
				proto_tree_add_item(p_tree, hf_pldm_base_nextDataTransferHandle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				proto_tree_add_item(p_tree, hf_pldm_base_transferFlag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;
				const char *version_string = ver2str(tvb, offset, pinfo);
				proto_tree_add_string_format_value(p_tree, hf_pldm_base_typeVersion, tvb, offset, 4,
				                                   version_string, "%s", version_string);
			}
			break;
		case 04: // GetPLDMTypes
			if (!request) {
				uint8_t flag_bit, curr_byte;
				int byte, bit;
				for (byte=0; byte<8; byte++, offset+=1) { // loop for iterating over last 8 bytes
					curr_byte = tvb_get_uint8(tvb, offset);
					flag_bit = 1; // bit within current byte
					for (bit=0; bit<8; bit++, flag_bit <<=1) {
						if (curr_byte & flag_bit) { // type is supported
							// Add bit position as value
							proto_tree_add_uint(p_tree, hf_pldm_base_typesSupported, tvb, offset, 1, (byte*8)+bit);
						}
					}
				}
			}
			break;
		case 05: // GetPLDMCommand
			if (request) {
				pldmT = tvb_get_uint8(tvb, offset); // response depends on this
				if (pldmT == 63)
					pldmT = 7; // for oem-specific inorder to avoid array of size 64
				if (instID > 31 || pldmT > 7) {
					col_append_str(pinfo->cinfo, COL_INFO, "Invalid PLDM Inst ID or Type");
					break;
				} else {
					pldmTypeMap = wmem_map_new(addr_resolv_scope, g_direct_hash, g_direct_equal);
					wmem_map_insert(pldmTypeMap, GUINT_TO_POINTER(instID), GUINT_TO_POINTER(pldmT));
				}
				proto_tree_add_item(p_tree, hf_pldm_base_PLDMtype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;
				const char *version_string = ver2str(tvb, offset, pinfo);
				proto_tree_add_string_format_value(p_tree, hf_pldm_base_typeVersion, tvb, offset, 4,
				                                   version_string, "%s", version_string);
			} else if (!request) {
				int pldmTypeReceived = GPOINTER_TO_UINT(wmem_map_lookup(pldmTypeMap, GUINT_TO_POINTER(instID)));
				switch (pldmTypeReceived) {
					case 0:
						{
							uint8_t byte = tvb_get_uint8(tvb, offset);
							uint8_t flag_bit = 1;
							for (int i = 0; i < 8; i++, flag_bit <<= 1) {
								if (byte & flag_bit) {
									proto_tree_add_uint(p_tree, hf_pldm_base_commands, tvb, offset, 1, i);
								}
							}
						}
						break;
					case 2:
						{
						    uint64_t byt[4];
						    byt[0] = tvb_get_letoh64(tvb, offset);
						    byt[1] = tvb_get_letoh64(tvb, offset + 8);
						    byt[2] = tvb_get_letoh64(tvb, offset + 16);
						    byt[3] = tvb_get_letoh64(tvb, offset + 24);
						    uint64_t flag_bit = 1;
						    for (int i = 0; i < 88; i++, flag_bit <<= 1) {
							    if (i == 64) {
								    flag_bit = 1;
							    }
							    int j = i / 64;
							    if (i > 7 && i % 8 == 0)
								    offset += 1;
							    uint64_t byte = byt[j];
							    if (byte & flag_bit) {
								    proto_tree_add_uint(p_tree, hf_pldm_platform_commands, tvb, offset, 1, i);
							    }
						    }
						}
					    break;
					case 3:
						{
						    uint16_t byte = tvb_get_letohs(tvb, offset);
						    uint16_t flag_bit = 1;
						    for (int i = 0; i < 16; i++, flag_bit <<= 1) {
							    if (i > 7 && i % 8 == 0)
								    offset += 1;
							    if (byte & flag_bit) {
								    proto_tree_add_uint(p_tree, hf_pldm_BIOS_commands, tvb, offset, 1, i);
							    }
						    }
						}
					    break;
					case 4:
						{
						    uint64_t byte = tvb_get_letoh64(tvb, offset);
						    uint64_t flag_bit = 1;
						    for (int i = 0; i < 64; i++, flag_bit <<= 1) {
							    if (i > 7 && i % 8 == 0)
								    offset += 1;
							    if (byte & flag_bit) {
								    proto_tree_add_uint(p_tree, hf_pldm_FRU_commands, tvb, offset, 1, i);
							    }
						    }
						}
					    break;
					default:
						   col_append_str(pinfo->cinfo, COL_INFO, "Invalid PLDM Command Request");
				}
			}
			break;
		default:
			col_append_str(pinfo->cinfo, COL_INFO, "Invalid PLDM command");
			break;
	}
	return tvb_captured_length(tvb);
}


static
int dissect_platform(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *p_tree, const pldm_packet_data *data)
{
	uint8_t request = data->direction;
	int    offset = 0;
	uint32_t pldm_cmd, completion_code;
	proto_tree_add_item_ret_uint(p_tree, hf_pldm_platform_commands, tvb, offset, 1, ENC_LITTLE_ENDIAN, &pldm_cmd);
	offset += 1;
	if (!request) { //completion code in response only
		proto_tree_add_item_ret_uint(p_tree, hf_pldm_platform_completion_code, tvb, offset, 1, ENC_LITTLE_ENDIAN, &completion_code);
		if (completion_code)
			return tvb_captured_length(tvb);
		offset += 1;
	}
	switch (pldm_cmd) {
		case 0x04: // Set Event Receiver command
			if (request) {
				uint32_t transport_protocol, event_message_global;
				proto_item *event_msg_global_response = proto_tree_add_item_ret_uint(
					p_tree, hf_event_message_global, tvb, offset, 1, ENC_LITTLE_ENDIAN, &event_message_global);
				offset += 1;
				proto_item *transport_protocol_response = proto_tree_add_item_ret_uint(
					p_tree, hf_transport_protocol_type, tvb, offset, 1, ENC_LITTLE_ENDIAN, &transport_protocol);
				offset += 1;
				if (transport_protocol_response != NULL && transport_protocol == 0) { // MCTP
					proto_tree_add_item(p_tree, hf_event_receiver_addr_info, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				}
				if (event_msg_global_response != NULL && event_message_global == 3) {
					offset += 1;
					proto_tree_add_item(p_tree, hf_heartbeat_timer, tvb, offset, 2, ENC_LITTLE_ENDIAN);
				}
			}
			break;
		case 0x0a: // Platform Event Message command
			if (request) {
				proto_tree_add_item(p_tree, hf_pldm_platform_format_version, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;
				proto_tree_add_item(p_tree, hf_pldm_base_TID, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;
				uint32_t platform_event_message_class;
				proto_tree_add_item_ret_uint(p_tree, hf_event_class, tvb, offset, 1, ENC_LITTLE_ENDIAN, &platform_event_message_class);
				offset += 1;
				uint32_t sensor_event_class;
				/* Event Data */
				switch (platform_event_message_class) {
					case 0x0: // SensorEvent(0x00)
						proto_tree_add_item(p_tree, hf_sensor_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
						offset += 2;
						proto_tree_add_item_ret_uint(p_tree, hf_sensor_event_class, tvb, offset, 1, ENC_LITTLE_ENDIAN, &sensor_event_class);
						offset += 1;
						/* Sensor Event Class */
						switch (sensor_event_class) {
							case 0x0: // Sensor Operational State
								proto_tree_add_item(p_tree, hf_sensor_present_op_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
								offset += 1;
								proto_tree_add_item(p_tree, hf_sensor_prev_op_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
								break;
							case 0x1: // State Sensor State
								proto_tree_add_item(p_tree, hf_sensor_offset, tvb, offset, 1, ENC_LITTLE_ENDIAN);
								offset += 1;
								proto_tree_add_item(p_tree, hf_event_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
								offset += 1;
								proto_tree_add_item(p_tree, hf_event_prev_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
								break;
							case 0x2: // Numeric Sensor State
								proto_tree_add_item(p_tree, hf_event_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
								offset += 1;
								proto_tree_add_item(p_tree, hf_event_prev_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
								offset += 1;
								uint32_t size;
								proto_tree_add_item_ret_uint(p_tree, hf_sensor_data_size, tvb, offset, 1, ENC_LITTLE_ENDIAN, &size);
								offset += 1;
								switch (size) {
									case 0:
										proto_tree_add_item(p_tree, hf_sensor_value_u8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
										break;
									case 1:
										proto_tree_add_item(p_tree, hf_sensor_value_s8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
										break;
									case 2:
										proto_tree_add_item(p_tree, hf_sensor_value_u16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
										break;
									case 3:
										proto_tree_add_item(p_tree, hf_sensor_value_s16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
										break;
									case 4:
										proto_tree_add_item(p_tree, hf_sensor_value_u32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
										break;
									case 5:
										proto_tree_add_item(p_tree, hf_sensor_value_s32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
										break;
									default: // Invalid
										col_append_str(pinfo->cinfo, COL_INFO, "Invalid byte");
								}
								break;
							default:
								col_append_str(pinfo->cinfo, COL_INFO, "Invalid sensor event class");
								break;
						}
						break;
					case 0x4: // PLDM PDR Repository Change Event
						if (request) {
							uint32_t pdr_data_format, num_change_record;
							proto_tree_add_item_ret_uint(p_tree, hf_pdr_data_format, tvb, offset, 1, ENC_LITTLE_ENDIAN, &pdr_data_format);
							offset += 1;
							proto_tree_add_item_ret_uint(p_tree, hf_pdr_num_change_recs, tvb, offset, 1, ENC_LITTLE_ENDIAN, &num_change_record);
							if (num_change_record>0) { // if pdr_data_format is refresh entire repo then num-change-record shall be 0
								offset +=1;
								for (uint32_t i = 0; i < num_change_record; i++) {
									proto_tree_add_item(p_tree, hf_pdr_repo_change_event_data_op, tvb, offset, 1, ENC_LITTLE_ENDIAN);
									offset +=1;
									uint32_t num_change_entries;
									proto_tree_add_item_ret_uint(p_tree, hf_pdr_repo_change_rec_num_change_entries, tvb, offset, 1, ENC_LITTLE_ENDIAN, &num_change_entries);
									offset +=1;
									for (uint32_t j = 0; j < num_change_entries; j++) {
										if (pdr_data_format == 1) { // pdr type enumeration
											proto_tree_add_item(p_tree, hf_pdr_repo_change_event_record_pdr_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
										}
										else if (pdr_data_format == 2) { // pdr Record handle enumeration
											proto_tree_add_item(p_tree, hf_pdr_repo_change_event_record_pdr_record_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
										}
										offset+=4;
									}
								}
							}
						}
						break;
					case 0x6: // Heartbeat elapsed
						if (request) {
							proto_tree_add_item(p_tree, hf_heartbeat_format_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
							offset += 1;
							proto_tree_add_item(p_tree, hf_heartbeat_sequence_num, tvb, offset, 1, ENC_LITTLE_ENDIAN);
						}
						break;
					default:
						col_append_str(pinfo->cinfo, COL_INFO, "Invalid platform message type");
				}
			}
			else {
				proto_tree_add_item(p_tree, hf_result_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			}
			break;
		case 0x21: // GetStateSensorReadings(33)
			if (request) {
				proto_tree_add_item(p_tree, hf_sensor_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
				offset += 2;
				uint8_t sensor_rearm = tvb_get_uint8(tvb, offset);
				uint8_t flag_bit = 1;
				int cnt = 0;
				for (int i = 0; i < 8; i++, flag_bit <<= 1) {
					if (sensor_rearm & flag_bit) {
						cnt++;
						proto_tree_add_uint(p_tree, hf_sensor_rearm, tvb, offset, 1, i);
					}
				}
				if (cnt == 0) {
					proto_tree_add_item(p_tree, hf_sensor_rearm_none, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				}
				offset +=1;
				proto_tree_add_item(p_tree, hf_pldm_sensor_reserved, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			} else {
				uint32_t sensor_comp_count;
				proto_tree_add_item_ret_uint(p_tree, hf_sensor_composite_count, tvb, offset, 1, ENC_LITTLE_ENDIAN, &sensor_comp_count);
				for (uint32_t i=0; i<sensor_comp_count; i++) { // statefield
					offset += 1;
					proto_tree_add_item(p_tree, hf_sensor_present_op_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
					offset += 1;
					proto_tree_add_item(p_tree, hf_sensor_present_event_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
					offset += 1;
					proto_tree_add_item(p_tree, hf_sensor_prev_event_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
					offset += 1;
					proto_tree_add_item(p_tree, hf_sensor_event_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				}
			}
			break;
		case 0x11: // GetSensorReading(17)
			if (request) {
				proto_tree_add_item(p_tree, hf_sensor_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
				offset += 2;
				proto_tree_add_item(p_tree, hf_event_rearm, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			}
			else {
				uint32_t size;
				proto_tree_add_item_ret_uint(p_tree, hf_sensor_data_size, tvb, offset, 1, ENC_LITTLE_ENDIAN, &size);
				offset += 1;
				proto_tree_add_item(p_tree, hf_sensor_present_op_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;
				proto_tree_add_item(p_tree, hf_sensor_event_msg_enable, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;
				proto_tree_add_item(p_tree, hf_sensor_present_event_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;
				proto_tree_add_item(p_tree, hf_sensor_prev_event_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;
				proto_tree_add_item(p_tree, hf_sensor_event_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;
				switch (size) {
					case 0:
						proto_tree_add_item(p_tree, hf_sensor_value_u8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
						break;
					case 1:
						proto_tree_add_item(p_tree, hf_sensor_value_s8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
						break;
					case 2:
						proto_tree_add_item(p_tree, hf_sensor_value_u16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
						break;
					case 3:
						proto_tree_add_item(p_tree, hf_sensor_value_s16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
						break;
					case 4:
						proto_tree_add_item(p_tree, hf_sensor_value_u32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
						break;
					case 5:
						proto_tree_add_item(p_tree, hf_sensor_value_s32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
						break;
					default: // Invalid
						col_append_str(pinfo->cinfo, COL_INFO, "Invalid byte");
				}
			}
			break;
		case 0x31: // SetNumericEffecterValue(49)
			if (request) {
				proto_tree_add_item(p_tree, hf_effecter_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
				offset += 2;
				uint32_t size;
				proto_tree_add_item_ret_uint(p_tree, hf_effecter_datasize, tvb, offset, 1, ENC_LITTLE_ENDIAN, &size);
				offset += 1;
				switch (size) {
					case 0:
						proto_tree_add_item(p_tree, hf_effecter_value_u8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
						break;
					case 1:
						proto_tree_add_item(p_tree, hf_effecter_value_s8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
						break;
					case 2:
						proto_tree_add_item(p_tree, hf_effecter_value_u16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
						break;
					case 3:
						proto_tree_add_item(p_tree, hf_effecter_value_s16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
						break;
					case 4:
						proto_tree_add_item(p_tree, hf_effecter_value_u32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
						break;
					case 5:
						proto_tree_add_item(p_tree, hf_effecter_value_s32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
						break;
					default: // Invalid
						col_append_str(pinfo->cinfo, COL_INFO, "Invalid byte");
				}
			}
			break;
		case 0x32: // GetNumericEffecterValue(50)
			if (request) {
				proto_tree_add_item(p_tree, hf_effecter_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			} else {
				uint32_t size;
				proto_tree_add_item_ret_uint(p_tree, hf_effecter_datasize, tvb, offset, 1, ENC_LITTLE_ENDIAN, &size);
				offset += 1;
				proto_tree_add_item(p_tree, hf_effecter_op_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;
				switch (size) {
					case 0:
						proto_tree_add_item(p_tree, hf_effecter_value_pnd_u8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
						offset += 1;
						proto_tree_add_item(p_tree, hf_effecter_value_pres_u8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
						break;
					case 1:
						proto_tree_add_item(p_tree, hf_effecter_value_pnd_s8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
						offset += 1;
						proto_tree_add_item(p_tree, hf_effecter_value_pres_s8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
						break;
					case 2:
						proto_tree_add_item(p_tree, hf_effecter_value_pnd_u16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
						offset += 2;
						proto_tree_add_item(p_tree, hf_effecter_value_pres_u16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
						break;
					case 3:
						proto_tree_add_item(p_tree, hf_effecter_value_pnd_s16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
						offset += 2;
						proto_tree_add_item(p_tree, hf_effecter_value_pres_s16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
						break;
					case 4:
						proto_tree_add_item(p_tree, hf_effecter_value_pnd_u32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
						offset += 4;
						proto_tree_add_item(p_tree, hf_effecter_value_pres_u32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
						break;
					case 5:
						proto_tree_add_item(p_tree, hf_effecter_value_pnd_s32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
						offset += 4;
						proto_tree_add_item(p_tree, hf_effecter_value_pres_s32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
						break;
					default: // Invalid
						col_append_str(pinfo->cinfo, COL_INFO, "Invalid byte");
				}

			}
			break;
		case 0x39: // SetStateEffecterStates(57)
			if (request) {
				proto_tree_add_item(p_tree, hf_effecter_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
				offset += 2;
				uint32_t effecter_comp_count;
				proto_tree_add_item_ret_uint(p_tree, hf_effecter_count, tvb, offset, 1, ENC_LITTLE_ENDIAN, &effecter_comp_count);
				for (uint32_t i=0; i < effecter_comp_count; i++) { // statefield
					offset += 1;
					proto_tree_add_item(p_tree, hf_effecter_set_request, tvb, offset, 1, ENC_LITTLE_ENDIAN);
					offset += 1;
					proto_tree_add_item(p_tree, hf_effecter_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				}
			}
			break;
		case 0x51: // GetPDR
			if (request) {
				proto_tree_add_item(p_tree, hf_pdr_record_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				proto_tree_add_item(p_tree, hf_pdr_data_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				proto_tree_add_item(p_tree, hf_pdr_transfer_op_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;
				proto_tree_add_item(p_tree, hf_pdr_req_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
				offset += 2;
				proto_tree_add_item(p_tree, hf_pdr_record_change_num, tvb, offset, 2, ENC_LITTLE_ENDIAN);

			} else {
				proto_tree_add_item(p_tree, hf_pdr_next_record_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				proto_tree_add_item(p_tree, hf_pdr_next_data_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				uint32_t transfer_flag;
				proto_tree_add_item_ret_uint(p_tree, hf_pdr_transfer_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN, &transfer_flag);
				offset += 1;
				uint32_t response_cnt;
				proto_tree_add_item_ret_uint(p_tree, hf_pdr_response_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &response_cnt);
				offset += 2;
				uint16_t pdr_length = tvb_reported_length_remaining(tvb, offset);
				if (response_cnt) {
					if (pdr_length != response_cnt) {
						col_append_str(pinfo->cinfo, COL_INFO, "Corrupt PDR Record data");
						break;
					}
					while (response_cnt > 0) {
						proto_tree_add_item(p_tree, hf_pdr_record_data, tvb, offset, 1, ENC_LITTLE_ENDIAN );
						offset += 1;
						response_cnt -= 1;
					}
				}
				if (transfer_flag == 0x4) {
					// CRC only present if flag == end
					proto_tree_add_item(p_tree, hf_transfer_crc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				}
			}
			break;
		default:
			col_append_fstr(pinfo->cinfo, COL_INFO, "Unsupported or Invalid PLDM command %x ", pldm_cmd);
			break;
	}
	return tvb_captured_length(tvb);
}

static
uint16_t parse_fru_record_table(tvbuff_t *tvb, const packet_info *pinfo,
	proto_tree *p_tree, uint16_t offset)
{
	uint32_t min_size = 8, field_len = 0, num_fields = 0, encoding = 0, record_type;
	uint16_t bytes_left = tvb_reported_length(tvb) - offset;
	while (bytes_left >= min_size) {
		// parse a FRU Record Data
		proto_tree_add_item(p_tree, hf_fru_record_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item_ret_uint(p_tree, hf_fru_record_type, tvb, offset, 1, ENC_LITTLE_ENDIAN, &record_type);
		offset += 1;
		proto_tree_add_item_ret_uint(p_tree, hf_fru_record_num_fields, tvb, offset, 1, ENC_LITTLE_ENDIAN, &num_fields);
		offset += 1;
		proto_tree_add_item_ret_uint(p_tree, hf_fru_record_encoding, tvb, offset, 1, ENC_LITTLE_ENDIAN, &encoding);
		offset += 1;

		for (uint8_t i = 0; i < num_fields; i++) {
			if (record_type == 1) { // General
				proto_tree_add_item(p_tree, hf_fru_record_field_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;
				proto_tree_add_item_ret_uint(p_tree, hf_fru_record_field_len, tvb, offset, 1, ENC_LITTLE_ENDIAN, &field_len);
				offset += 1;
				switch (encoding) {
					case 0x1:
						proto_tree_add_item(p_tree, hf_fru_record_field_value, tvb, offset, field_len, ENC_ISO_8859_1);
						break;
					case 0x2:
						proto_tree_add_item(p_tree, hf_fru_record_field_value, tvb, offset, field_len, ENC_UTF_8);
						break;
					case 0x3:
						proto_tree_add_item(p_tree, hf_fru_record_field_value, tvb, offset, field_len, ENC_UTF_16 | ENC_BOM);
						break;
					case 0x4:
						proto_tree_add_item(p_tree, hf_fru_record_field_value, tvb,
											offset, field_len, ENC_UTF_16 | ENC_LITTLE_ENDIAN);
						break;
					case 0x5:
						proto_tree_add_item(p_tree, hf_fru_record_field_value, tvb,
											offset, field_len, ENC_UTF_16 | ENC_BIG_ENDIAN);
						break;
					default:
						col_append_str(pinfo->cinfo, COL_INFO, "Unsupported or invalid FRU record encoding");
						break;
				}
				offset += field_len;
			} else {
				col_append_str(pinfo->cinfo, COL_INFO, "Unsupported or OEM FRU record type");
			}
		}
		bytes_left = tvb_reported_length(tvb) - offset;
	}
	return offset;
};

static
int dissect_FRU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *p_tree, const pldm_packet_data *data)
{
	uint8_t request = data->direction;
	uint16_t offset = 0;
	uint32_t pldm_cmd;
	uint8_t padding = 0;
	proto_tree_add_item_ret_uint(p_tree, hf_pldm_FRU_commands, tvb, offset, 1, ENC_LITTLE_ENDIAN, &pldm_cmd);
	offset += 1;
	if (!request) {
		uint8_t completion_code = tvb_get_uint8(tvb, offset);
		switch (completion_code) {
			case 0x80:
			case 0x81:
			case 0x82:
			case 0x83:
			case 0x84:
			case 0x85:
				proto_tree_add_item(p_tree, hf_fru_completion_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				break;
			default:
				proto_tree_add_item(p_tree, hf_pldm_completion_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		}

		if (completion_code)
			return tvb_captured_length(tvb);
		offset += 1;
	}
	switch (pldm_cmd) {
		case 0x01: // Get Fru record table metadata
			if (!request) {
				proto_tree_add_item(p_tree, hf_fru_major_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;
				proto_tree_add_item(p_tree, hf_fru_minor_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;
				proto_tree_add_item(p_tree, hf_fru_table_max_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				proto_tree_add_item(p_tree, hf_fru_table_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				proto_tree_add_item(p_tree, hf_fru_num_record_identifiers, tvb, offset, 2, ENC_LITTLE_ENDIAN);
				offset += 2;
				proto_tree_add_item(p_tree, hf_fru_num_records, tvb, offset, 2, ENC_LITTLE_ENDIAN);
				offset += 2;
				proto_tree_add_item(p_tree, hf_fru_table_crc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			}
			break;
		case 0x02: // Get Fru record table
			if (request) {
				proto_tree_add_item(p_tree, hf_fru_data_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				proto_tree_add_item(p_tree, hf_fru_transfer_op_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			} else {
				proto_tree_add_item(p_tree, hf_fru_next_data_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				proto_tree_add_item(p_tree, hf_fru_transfer_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;
				offset = parse_fru_record_table(tvb, pinfo, p_tree, offset);//check
				if (tvb_captured_length(tvb) != offset)
					col_append_str(pinfo->cinfo, COL_INFO, "Unexpected bytes at end of FRU table");
			}
			break;
		case 0x03: // Set Fru record table
			if (request) {
				proto_tree_add_item(p_tree, hf_fru_data_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				proto_tree_add_item(p_tree, hf_pldm_base_transferFlag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;
				offset = parse_fru_record_table(tvb, pinfo, p_tree, offset);//check
				if (tvb_captured_length(tvb) != offset) {
					padding = tvb_captured_length(tvb) - offset - 4;
					offset += padding;
					proto_tree_add_item(p_tree, hf_fru_record_crc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				}
			} else {
				proto_tree_add_item(p_tree, hf_fru_next_data_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			}
			break;
		case 0x04: // GetFruRecordByOption
			if (request) {
				proto_tree_add_item(p_tree, hf_fru_data_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				proto_tree_add_item(p_tree, hf_fru_table_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
				offset += 2;
				proto_tree_add_item(p_tree, hf_fru_record_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
				offset += 2;
				proto_tree_add_item(p_tree, hf_fru_record_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;
				proto_tree_add_item(p_tree, hf_fru_record_field_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset +=1;
				proto_tree_add_item(p_tree, hf_fru_transfer_op_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			} else {
				proto_tree_add_item(p_tree, hf_fru_next_data_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				proto_tree_add_item(p_tree, hf_pldm_base_transferFlag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;
				offset = parse_fru_record_table(tvb, pinfo, p_tree, offset); // check
				if (tvb_captured_length(tvb) != offset) {
					padding = tvb_captured_length(tvb) - offset - 4;
					offset += padding;
					proto_tree_add_item(p_tree, hf_fru_record_crc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				}
			}
			break;
		default:
			col_append_str(pinfo->cinfo, COL_INFO, "Unsupported or Invalid PLDM command");
			break;
	}
	return tvb_captured_length(tvb);
}

void dissect_bios_string_table(tvbuff_t *tvb, proto_tree *p_tree,
                               int *offset, packet_info *pinfo, int sz) {
	uint16_t len = tvb_reported_length(tvb);
	len = len - sz;
	uint16_t rem_bytes = len;
	int L=0;
	uint32_t str_len = 0;
	int num_pad_bytes = 0;
	while (rem_bytes >= 8) {
		proto_tree_add_item(p_tree, hf_bios_str_handle, tvb, *offset, 2,
							ENC_LITTLE_ENDIAN);
		*offset += 2;
		proto_tree_add_item_ret_uint(p_tree, hf_bios_str_len, tvb, *offset, 2,
							ENC_LITTLE_ENDIAN, &str_len);
		if (str_len >= (uint32_t)(rem_bytes - 4)) break;
		*offset += 2;
		L+=4;
		proto_tree_add_item(p_tree, hf_bios_str, tvb, *offset, str_len, ENC_ASCII);
		proto_item_append_text(
			p_tree, ": %s",
			tvb_get_string_enc(pinfo->pool, tvb, *offset, str_len, ENC_ASCII));
		L+=str_len;
		*offset += str_len;
		rem_bytes = rem_bytes - 4 - str_len;
		str_len = 0;
	}   

	num_pad_bytes = rem_bytes % 4;
	if (num_pad_bytes>0){
		num_pad_bytes = 4 - (L%4);
		proto_tree_add_item(p_tree, hf_bios_attr_table_pad_bytes, tvb, *offset,
							num_pad_bytes, ENC_LITTLE_ENDIAN);
		*offset += num_pad_bytes;
		int reported_length = tvb_reported_length_remaining(tvb, *offset);
		if (reported_length>=4){
			proto_tree_add_item(p_tree, hf_bios_attr_table_checksum, tvb, *offset, 4,
							ENC_LITTLE_ENDIAN);
		}
	}              
	return;                 
}   
    
void dissect_bios_attribute_table(tvbuff_t *tvb, proto_tree *p_tree,
                                  int *offset, packet_info *pinfo, int sz) {

	uint16_t len = tvb_reported_length(tvb);
	len = len - sz;
	uint16_t rem_bytes = len;
	int len_attr_fields = 0;
	int L=0;
	uint32_t num_values = 0;
	uint32_t attr_type = 0;
	int num_pad_bytes = 0;
	while (rem_bytes >= 8) {
		proto_tree_add_item_ret_uint(p_tree, hf_bios_attr_handle, tvb, *offset, 2,
							ENC_LITTLE_ENDIAN, &attr_type);
		*offset += 2;
		proto_tree_add_item(p_tree, hf_bios_attr_type, tvb, *offset, 1,
							ENC_LITTLE_ENDIAN);
		*offset += 1;
		proto_tree_add_item(p_tree, hf_bios_attr_name_handle, tvb, *offset, 2,
							ENC_LITTLE_ENDIAN);
		*offset += 2;
		L+=5;
		switch (attr_type){
			case 0:
			case 128:
				proto_tree_add_item_ret_uint(p_tree, hf_bios_enumer_num_pos_values, tvb, *offset,
								1, ENC_LITTLE_ENDIAN, &num_values);
				*offset += 1;
				len_attr_fields += 1;
				while (num_values > 0) {
					proto_tree_add_item(p_tree, hf_bios_enumer_pos_value_str_hndl, tvb,
										*offset, 2, ENC_LITTLE_ENDIAN);
					*offset += 2;
					len_attr_fields += 2;
					num_values--;
				}
				proto_tree_add_item_ret_uint(p_tree, hf_bios_enumer_num_default_values, tvb,
									*offset, 1, ENC_LITTLE_ENDIAN, &num_values);
				*offset += 1;
				len_attr_fields += 1;
				while (num_values > 0) {
					proto_tree_add_item(p_tree, hf_bios_enumer_default_value_str_hndl, tvb,
										*offset, 1, ENC_LITTLE_ENDIAN);
					*offset += 1;
					len_attr_fields += 1;
					num_values--;
				}
				break;
			case 1:
			case 129:
				proto_tree_add_item(p_tree, hf_bios_string_type, tvb, *offset, 1,
								ENC_LITTLE_ENDIAN);
				*offset += 1;
				len_attr_fields += 1;
				proto_tree_add_item(p_tree, hf_bios_min_str_len, tvb, *offset, 2,
									ENC_LITTLE_ENDIAN);
				*offset += 2;
				len_attr_fields += 2;
				proto_tree_add_item(p_tree, hf_bios_max_str_len, tvb, *offset, 2,
									ENC_LITTLE_ENDIAN);
				*offset += 2;
				len_attr_fields += 2;
				uint32_t def_str_len;
				proto_tree_add_item_ret_uint(p_tree, hf_bios_def_str_len, tvb, *offset, 2,
									ENC_LITTLE_ENDIAN, &def_str_len);
				*offset += 2;
				len_attr_fields += 2;
				if (def_str_len != 0) {
					proto_tree_add_item(p_tree, hf_bios_def_str, tvb, *offset, def_str_len,
										ENC_ASCII);
					proto_item_append_text(p_tree, ": %s",
											tvb_get_string_enc(pinfo->pool, tvb, *offset,
																def_str_len, ENC_ASCII));
					*offset += def_str_len;
					len_attr_fields += def_str_len;
				}
				break;
			case 2:
			case 130:
				proto_tree_add_item(p_tree, hf_bios_pass_type, tvb, *offset, 1,
								ENC_LITTLE_ENDIAN);
				*offset += 1;
				len_attr_fields += 1;
				proto_tree_add_item(p_tree, hf_bios_min_pass_len, tvb, *offset, 2,
									ENC_LITTLE_ENDIAN);
				*offset += 2;
				len_attr_fields += 2;
				proto_tree_add_item(p_tree, hf_bios_max_pass_len, tvb, *offset, 2,
									ENC_LITTLE_ENDIAN);
				*offset += 2;
				len_attr_fields += 2;
				uint32_t def_pass_len;
				proto_tree_add_item_ret_uint(p_tree, hf_bios_def_pass_len, tvb, *offset, 2,
									ENC_LITTLE_ENDIAN, &def_pass_len);
				*offset += 2;
				len_attr_fields += 2;
				if (def_pass_len != 0) {
					proto_tree_add_item_ret_uint(p_tree, hf_bios_def_pass, tvb, *offset,
										hf_bios_def_str_len, ENC_LITTLE_ENDIAN, &def_pass_len);
					*offset += def_pass_len;
					len_attr_fields += def_pass_len;
				}
				break;
			case 3:
			case 131:
				proto_tree_add_item(p_tree, hf_bios_int_lower_bound, tvb, *offset, 8,
								ENC_LITTLE_ENDIAN);
				*offset += 8;
				len_attr_fields += 8;
				proto_tree_add_item(p_tree, hf_bios_int_upper_bound, tvb, *offset, 8,
									ENC_LITTLE_ENDIAN);
				*offset += 8;
				len_attr_fields += 8;
				proto_tree_add_item(p_tree, hf_bios_int_scalar_inc, tvb, *offset, 4,
									ENC_LITTLE_ENDIAN);
				*offset += 4;
				len_attr_fields += 4;
				proto_tree_add_item(p_tree, hf_bios_int_def_val, tvb, *offset, 8,
									ENC_LITTLE_ENDIAN);
				*offset += 8;
				len_attr_fields += 8;
				break;
			case 4:
			case 132:
				proto_tree_add_item(p_tree, hf_bios_boot_config_type, tvb, *offset, 1,
								ENC_LITTLE_ENDIAN);
				*offset += 1;
				len_attr_fields += 1;
				proto_tree_add_item(p_tree, hf_bios_fail_through_modes, tvb, *offset, 1,
									ENC_LITTLE_ENDIAN);
				*offset += 1;
				len_attr_fields += 1;
				proto_tree_add_item(p_tree, hf_bios_min_num_boot_src, tvb, *offset, 1,
									ENC_LITTLE_ENDIAN);
				*offset += 1;
				len_attr_fields += 1;
				proto_tree_add_item(p_tree, hf_bios_max_num_boot_src, tvb, *offset, 1,
									ENC_LITTLE_ENDIAN);
				*offset += 1;
				len_attr_fields += 1;
				proto_tree_add_item_ret_uint(p_tree, hf_bios_pos_num_boot_src, tvb, *offset, 1,
									ENC_LITTLE_ENDIAN, &num_values);
				*offset += 1;
				len_attr_fields += 1;
				while (num_values > 0) {
					proto_tree_add_item(p_tree, hf_bios_src_str_hndl, tvb, *offset, 2,
										ENC_LITTLE_ENDIAN);
					*offset += 2;
					len_attr_fields += 2;
					num_values--;
				}
				break;
			case 5:
			case 133:
				proto_tree_add_item(p_tree, hf_bios_col_name_str_hndl, tvb, *offset, 2,
								ENC_LITTLE_ENDIAN);
				*offset += 2;
				len_attr_fields += 2;
				proto_tree_add_item(p_tree, hf_bios_max_num_attr, tvb, *offset, 1,
									ENC_LITTLE_ENDIAN);
				*offset += 1;
				len_attr_fields += 1;
				proto_tree_add_item(p_tree, hf_bios_col_type, tvb, *offset, 1,
									ENC_LITTLE_ENDIAN);
				*offset += 1;
				len_attr_fields += 1;
				break;
			case 6:
			case 134:
				proto_tree_add_item_ret_uint(p_tree, hf_bios_num_pos_config, tvb, *offset, 1,
								ENC_LITTLE_ENDIAN, &num_values);
				*offset += 1;
				len_attr_fields += 1;
				while (num_values > 0) {
					proto_tree_add_item(p_tree, hf_bios_pos_config_str_hndl, tvb, *offset,
										2, ENC_LITTLE_ENDIAN);
					*offset += 2;
					len_attr_fields += 2;
					num_values--;
				}
				break;
			default: 
				col_append_str(pinfo->cinfo, COL_INFO, "Unsupported or Invalid attribute type");
				break;
		}
		rem_bytes = rem_bytes - 5 - len_attr_fields;
		L+=len_attr_fields;
		len_attr_fields = 0;
	}
	num_pad_bytes = rem_bytes % 4;
	if (num_pad_bytes>0){
		num_pad_bytes = 4 - (L%4);
		proto_tree_add_item(p_tree, hf_bios_attr_table_pad_bytes, tvb, *offset,
							num_pad_bytes, ENC_LITTLE_ENDIAN); 
		*offset += num_pad_bytes;
		int reported_length = tvb_reported_length_remaining(tvb, *offset);
		if (reported_length>=4){
			proto_tree_add_item(p_tree, hf_bios_attr_table_checksum, tvb, *offset, 4,
							ENC_LITTLE_ENDIAN);
		}
	}
	return;
}

void dissect_bios_attribute_val_table(tvbuff_t *tvb, proto_tree *p_tree,
                                      int *offset, packet_info *pinfo, int sz) {
	uint16_t len = tvb_reported_length(tvb);
	len = len - sz;
	uint16_t rem_bytes = len;
	int len_attr_fields = 0;
	int L=0;
	uint32_t num_values = 0;
	uint32_t attr_type = 0;
	int num_pad_bytes = 0;
	while (rem_bytes >= 8 && rem_bytes > 0) {
		proto_tree_add_item(p_tree, hf_bios_attr_handle, tvb, *offset, 2,
							ENC_LITTLE_ENDIAN);
		*offset += 2;
		proto_tree_add_item_ret_uint(p_tree, hf_bios_attr_type, tvb, *offset, 1,
							ENC_LITTLE_ENDIAN, &attr_type);
		*offset += 1;
		L+=3;
		switch (attr_type){
			case 0:
			case 128:
				proto_tree_add_item_ret_uint(p_tree, hf_bios_enumer_num_cur_values, tvb, *offset,
								1, ENC_LITTLE_ENDIAN, &num_values);
				*offset += 1;
				len_attr_fields += 1;
				while (num_values > 0) {
					proto_tree_add_item(p_tree, hf_bios_enumer_cur_value_str_hndl, tvb,
										*offset, 1, ENC_LITTLE_ENDIAN);
					*offset += 1;
					len_attr_fields += 1;
					num_values--;
				}
				break;
			case 1:
			case 129:
				{
					uint32_t cur_str_len =0;
					proto_tree_add_item_ret_uint(p_tree, hf_bios_cur_str_len, tvb, *offset, 2,
										ENC_LITTLE_ENDIAN, &cur_str_len);
					*offset += 2;
					len_attr_fields += 2;
					if (cur_str_len > 0){
						proto_tree_add_item(p_tree, hf_bios_def_str, tvb, *offset, cur_str_len,
											ENC_ASCII);
						proto_item_append_text(p_tree, ": %s",
												tvb_get_string_enc(pinfo->pool, tvb, *offset,
																	cur_str_len, ENC_ASCII));
					}
					*offset += cur_str_len;
					len_attr_fields += cur_str_len;
				}
				break;
			case 2:
			case 130:
				proto_tree_add_item(p_tree, hf_bios_cur_pass_len, tvb, *offset, 2,
								ENC_LITTLE_ENDIAN);
				*offset += 2;
				len_attr_fields += 2;
				uint32_t cur_pass_len;
				proto_tree_add_item_ret_uint(p_tree, hf_bios_cur_pass, tvb, *offset,
									hf_bios_cur_pass_len, ENC_LITTLE_ENDIAN, &cur_pass_len);
				*offset += cur_pass_len;
				len_attr_fields += cur_pass_len;
				break;
			case 3:
			case 131:
				proto_tree_add_item(p_tree, hf_bios_cur_val, tvb, *offset, 8,
								ENC_LITTLE_ENDIAN);
				*offset += 8;
				len_attr_fields += 8;
				break;
			case 4:
			case 132:
				proto_tree_add_item(p_tree, hf_bios_boot_config_type, tvb, *offset, 1,
								ENC_LITTLE_ENDIAN);
				*offset += 1;
				len_attr_fields += 1;
				proto_tree_add_item(p_tree, hf_bios_fail_through_modes, tvb, *offset, 1,
									ENC_LITTLE_ENDIAN);
				*offset += 1;
				len_attr_fields += 1;
				proto_tree_add_item_ret_uint(p_tree, hf_bios_num_boot_src, tvb, *offset, 1,
									ENC_LITTLE_ENDIAN, &num_values);
				*offset += 1;
				len_attr_fields += 1;
				while (num_values > 0) {
					proto_tree_add_item(p_tree, hf_bios_boot_src_str_hndl, tvb, *offset, 1,
										ENC_LITTLE_ENDIAN);
					*offset += 1;
					len_attr_fields += 1;
					num_values--;
				}
				break;
			case 5:
			case 133:
				proto_tree_add_item_ret_uint(p_tree, hf_bios_num_attr, tvb, *offset, 1,
								ENC_LITTLE_ENDIAN, &num_values);
				*offset += 1;
				len_attr_fields += 1;
				while (num_values > 0) {
					proto_tree_add_item(p_tree, hf_bios_attr_hndl, tvb, *offset, 2,
										ENC_LITTLE_ENDIAN);
					*offset += 2;
					len_attr_fields += 2;
					num_values--;
				}
				break;
			case 6:
			case 134:
				proto_tree_add_item(p_tree, hf_bios_cur_config_set_str_hndl, tvb,
								(*offset), 1, ENC_LITTLE_ENDIAN);
				*offset += 1;
				len_attr_fields += 1;
				break;
			default:
				col_append_str(pinfo->cinfo, COL_INFO, "Unsupported or Invalid attribute type");
				break;
		}
		rem_bytes = rem_bytes - 3 - len_attr_fields;
		L+=len_attr_fields;
		len_attr_fields = 0;
	}
	num_pad_bytes = rem_bytes % 4;
	if (num_pad_bytes>0){
		num_pad_bytes = 4 - (L%4);
		proto_tree_add_item(p_tree, hf_bios_attr_table_pad_bytes, tvb, *offset,
							num_pad_bytes, ENC_LITTLE_ENDIAN);
		*offset += num_pad_bytes;
		int reported_length = tvb_reported_length_remaining(tvb, *offset);
		if (reported_length>=4){
			proto_tree_add_item(p_tree, hf_bios_attr_table_checksum, tvb, *offset, 4,
							ENC_LITTLE_ENDIAN);
		}
	}
	return;
}

void dissect_bios_attribute_pending_val_table(tvbuff_t *tvb, proto_tree *p_tree,
                                              int *offset, packet_info *pinfo __attribute__((unused)), int sz) {
	uint16_t len = tvb_reported_length(tvb);
	len = len - sz;
	uint16_t rem_bytes = len;
	int len_attr_fields = 0;
	int L=0;
	uint32_t num_values = 0;
	uint32_t attr_type = 0;
	int num_pad_bytes = 0;
	while (rem_bytes >= 8 && rem_bytes > 0) {
		proto_tree_add_item(p_tree, hf_bios_attr_handle, tvb, *offset, 2,
							ENC_LITTLE_ENDIAN);
		*offset += 2;
		proto_tree_add_item_ret_uint(p_tree, hf_bios_attr_type, tvb, *offset, 1,
							ENC_LITTLE_ENDIAN, &attr_type);
		*offset += 1;
		L+=3;
		switch (attr_type)
		{
			case 0:
				proto_tree_add_item_ret_uint(p_tree, hf_bios_enumer_num_pen_values, tvb, *offset,
								1, ENC_LITTLE_ENDIAN, &num_values);
				*offset += 1;
				len_attr_fields += 1;
				while (num_values > 0) {
					proto_tree_add_item(p_tree, hf_bios_enumer_pen_value_str_hndl, tvb,
										*offset, 1, ENC_LITTLE_ENDIAN);
					*offset += 1;
					len_attr_fields += 1;
					num_values--;
				}
				break;
			case 1:
				{
					uint32_t pen_str_len;
					proto_tree_add_item_ret_uint(p_tree, hf_bios_pen_str_len, tvb, *offset, 2,
										ENC_LITTLE_ENDIAN, &pen_str_len);
					*offset += 2;
					len_attr_fields += 2;
					proto_tree_add_item(p_tree, hf_bios_pen_str, tvb, *offset,
										hf_bios_cur_str_len, ENC_LITTLE_ENDIAN);
					*offset += pen_str_len;
					len_attr_fields += pen_str_len;
				}
				break;
			case 2:
				{
					uint32_t pen_pass_len;
					proto_tree_add_item_ret_uint(p_tree, hf_bios_pen_pass_len, tvb, *offset, 2,
										ENC_LITTLE_ENDIAN, &pen_pass_len);
					*offset += 2;
					len_attr_fields += 2;
					proto_tree_add_item(p_tree, hf_bios_pen_pass, tvb, *offset,
										hf_bios_cur_pass_len, ENC_LITTLE_ENDIAN);
					*offset += pen_pass_len;
					len_attr_fields += pen_pass_len;
				}
				break;
			case 3:
				proto_tree_add_item(p_tree, hf_bios_pen_val, tvb, *offset, 8,
								ENC_LITTLE_ENDIAN);
				*offset += 8;
				len_attr_fields += 8;
				break;
			case 4:
				proto_tree_add_item(p_tree, hf_bios_boot_config_type, tvb, *offset, 1,
								ENC_LITTLE_ENDIAN);
				*offset += 1;
				len_attr_fields += 1;
				proto_tree_add_item(p_tree, hf_bios_fail_through_modes, tvb, *offset, 1,
									ENC_LITTLE_ENDIAN);
				*offset += 1;
				len_attr_fields += 1;
				proto_tree_add_item_ret_uint(p_tree, hf_bios_num_pen_boot_src, tvb, *offset, 1,
									ENC_LITTLE_ENDIAN, &num_values);
				*offset += 1;
				len_attr_fields += 1;
				while (num_values > 0) {
					proto_tree_add_item(p_tree, hf_bios_boot_src_str_hndl, tvb, *offset, 1,
										ENC_LITTLE_ENDIAN);
					*offset += 1;
					len_attr_fields += 1;
					num_values--;
				}
				break;
			case 5:
			case 133:
				proto_tree_add_item_ret_uint(p_tree, hf_bios_num_attr, tvb, *offset, 1,
								ENC_LITTLE_ENDIAN, &num_values);
				*offset += 1;
				len_attr_fields += 1;
				while (num_values > 0) {
					proto_tree_add_item(p_tree, hf_bios_attr_hndl, tvb, *offset, 2,
										ENC_LITTLE_ENDIAN);
					*offset += 2;
					len_attr_fields += 2;
					num_values--;
				}
				break;
			case 6:
				proto_tree_add_item(p_tree, hf_bios_config_set_str_hndl, tvb, *offset, 1,
								ENC_LITTLE_ENDIAN);
				*offset += 1;
				len_attr_fields += 1;
				break;
			default:
				col_append_str(pinfo->cinfo, COL_INFO, "Unsupported or Invalid attribute type");
				break;
		}
		rem_bytes = rem_bytes - 3 - len_attr_fields;
		L+=len_attr_fields;
		len_attr_fields = 0;
	}
	num_pad_bytes = rem_bytes % 4;
	if (num_pad_bytes>0){
		num_pad_bytes = 4 - (L%4);
		proto_tree_add_item(p_tree, hf_bios_attr_table_pad_bytes, tvb, *offset,
							num_pad_bytes, ENC_LITTLE_ENDIAN);
		*offset += num_pad_bytes;
		int reported_length = tvb_reported_length_remaining(tvb, *offset);
		if (reported_length>=4){
			proto_tree_add_item(p_tree, hf_bios_attr_table_checksum, tvb, *offset, 4,
							ENC_LITTLE_ENDIAN);
		}
	}
	return;
}

int dissect_bios(tvbuff_t *tvb, packet_info *pinfo __attribute__((unused)) , proto_tree *p_tree,
                 const pldm_packet_data *data) {				
	uint8_t request = data->direction;
	int offset = 0;
	uint32_t pldm_cmd;
	uint8_t hour, min, sec;
	static uint32_t table_type = 0;
	int bytes_traversed =0;
	proto_tree_add_item_ret_uint(p_tree, hf_pldm_BIOS_commands, tvb, offset, 1, ENC_LITTLE_ENDIAN, &pldm_cmd);
	offset += 1;
	bytes_traversed+=1;
	if (!request) {
		uint32_t completion_code;
		proto_tree_add_item_ret_uint(p_tree, hf_pldm_completion_code, tvb, offset, 1,
							ENC_LITTLE_ENDIAN, &completion_code);
		if (completion_code)
			return tvb_captured_length(tvb);
		offset += 1;
		bytes_traversed+=1;
  	}
	switch (pldm_cmd) {
	case 0x1: // Get BIOS Table
		if (request) {
			proto_tree_add_item(p_tree, hf_bios_data_handle, tvb, offset, 4,
								ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(p_tree, hf_pldm_base_transferOperationFlag, tvb, offset, 1,
								ENC_LITTLE_ENDIAN);
			offset += 1;
			proto_tree_add_item_ret_uint(p_tree, hf_bios_table_type, tvb, offset, 1,
								ENC_LITTLE_ENDIAN, &table_type);
		} else {
			proto_tree_add_item(p_tree, hf_bios_next_data_handle, tvb, offset, 4,
								ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(p_tree, hf_bios_transfer_flag, tvb, offset, 1,
								ENC_LITTLE_ENDIAN);
			offset += 1;
			bytes_traversed += 5;
			switch (table_type){
				case 0: 
					dissect_bios_string_table(tvb, p_tree, &offset, pinfo, bytes_traversed);
					break;
				case 1:
					dissect_bios_attribute_table(tvb, p_tree, &offset, pinfo, bytes_traversed);
					break;
				case 2:
					dissect_bios_attribute_val_table(tvb, p_tree, &offset, pinfo, bytes_traversed);
					break;
				case 3:
					dissect_bios_attribute_pending_val_table(tvb, p_tree, &offset, pinfo, bytes_traversed);
					break;
				default:
					col_append_str(pinfo->cinfo, COL_INFO, "Unsupported or Invalid BIOS table type");
					break;
			}
		}
		break;
	case 0x02: // Set BIOS Table
		if (request) {
			proto_tree_add_item(p_tree, hf_bios_data_handle, tvb, offset, 4,
								ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(p_tree, hf_bios_transfer_flag, tvb, offset, 1,
								ENC_LITTLE_ENDIAN);
			offset += 1;
			proto_tree_add_item_ret_uint(p_tree, hf_bios_table_type, tvb, offset, 1,
								ENC_LITTLE_ENDIAN, &table_type);
			offset += 1;
			bytes_traversed += 6;
			switch (table_type){
				case 0: 
					dissect_bios_string_table(tvb, p_tree, &offset, pinfo, bytes_traversed);
					break;
				case 1:
					dissect_bios_attribute_table(tvb, p_tree, &offset, pinfo, bytes_traversed);
					break;
				case 2:
					dissect_bios_attribute_val_table(tvb, p_tree, &offset, pinfo, bytes_traversed);
					break;
				default:
					col_append_str(pinfo->cinfo, COL_INFO, "Unsupported or Invalid table type");
					break;
			}
		} else {
			proto_tree_add_item(p_tree, hf_bios_next_data_handle, tvb, offset, 4,
								ENC_LITTLE_ENDIAN);
		}
		break;
	case 0x07: // Set BIOS Attribute Current Value
		if (request) {
			proto_tree_add_item(p_tree, hf_bios_data_handle, tvb, offset, 4,
								ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(p_tree, hf_bios_transfer_flag, tvb, offset, 1,
								ENC_LITTLE_ENDIAN);
			offset += 1;
			proto_tree_add_item(p_tree, hf_bios_attr_handle, tvb, offset, 2,
									ENC_LITTLE_ENDIAN);
			offset += 2;
			uint32_t attr_type;
			proto_tree_add_item_ret_uint(p_tree, hf_bios_attr_type, tvb, offset, 1,
									ENC_LITTLE_ENDIAN, &attr_type);
			offset += 1;
			switch (attr_type)
			{
				case 0x00://BIOS Enum
				case 0x80:
						{
							uint32_t num_curr_val =0;
							proto_tree_add_item_ret_uint(p_tree, hf_bios_num_curr_value, tvb, offset, 1,
													ENC_LITTLE_ENDIAN, &num_curr_val);
							offset += 1;
							for (uint8_t i = 0; i < num_curr_val; i++, offset+=1){
								proto_tree_add_item(p_tree, hf_bios_enum_curr_str_hndl_idx, tvb, offset, 1, ENC_LITTLE_ENDIAN);
							}
						}
					break;
				case 0x01://BIOS String
				case 0x81:
						{
							uint32_t cur_str_length=0;
							proto_tree_add_item_ret_uint(p_tree, hf_bios_cur_str_len, tvb, offset, 2,
									ENC_LITTLE_ENDIAN, &cur_str_length);
							offset += 2;
							if (cur_str_length > 0){
								proto_tree_add_item(p_tree, hf_bios_def_str, tvb, offset, cur_str_length,
													ENC_ASCII);
								proto_item_append_text(p_tree, ": %s",
													tvb_get_string_enc(pinfo->pool, tvb, offset,
																		cur_str_length, ENC_ASCII));
							}
						} 
					break;
				case 0x02://BIOS Password
				case 0x82://BIOS Password Read Only
						proto_tree_add_item(p_tree, hf_bios_cur_pass_len, tvb, offset, 2,
								ENC_LITTLE_ENDIAN);
						offset += 2;
						uint32_t cur_pass_len;
						proto_tree_add_item_ret_uint(p_tree, hf_bios_cur_pass, tvb, offset,
											hf_bios_cur_pass_len, ENC_LITTLE_ENDIAN, &cur_pass_len);
						offset += cur_pass_len;
					break;
				case 0x03://BIOS Integer
				case 0x83://BIOS Integer Read Only
						proto_tree_add_item(p_tree, hf_bios_cur_val, tvb, offset, 8,
								ENC_LITTLE_ENDIAN);
						offset += 8;
					break;
				case 0x04://BIOS Boot Config Setting
				case 0x84://BIOS Boot Config Setting ReadOnly
						proto_tree_add_item(p_tree, hf_bios_boot_config_type, tvb, offset, 1,
											ENC_LITTLE_ENDIAN);
						offset += 1;
						proto_tree_add_item(p_tree, hf_bios_fail_through_modes, tvb, offset, 1,
											ENC_LITTLE_ENDIAN);
						offset += 1;
							uint32_t num_boot_values;
						proto_tree_add_item_ret_uint(p_tree, hf_bios_num_boot_src, tvb, offset, 1,
											ENC_LITTLE_ENDIAN, &num_boot_values);
						offset += 1;
						for (uint8_t i=0; i < num_boot_values ; i++) {
							proto_tree_add_item(p_tree, hf_bios_boot_src_str_hndl, tvb, offset, 1, i);
							offset += 1;
						}
					break;
				case 0x05://BIOS Collection
				case 0x85://BIOS Collection Read Only
						{
							uint32_t num_attr_values;
							proto_tree_add_item_ret_uint(p_tree, hf_bios_num_attr, tvb, offset, 1,
												ENC_LITTLE_ENDIAN, &num_attr_values);
							offset += 1;
							for (uint8_t i=0; i < num_attr_values ; i++) {
								proto_tree_add_item(p_tree, hf_bios_attr_hndl, tvb, offset, 2,
													i);
								offset += 2;
							}
						}			
					break;
				case 0x06://BIOS Config Set
				case 0x86://BIOS Config Set
						proto_tree_add_item(p_tree, hf_bios_config_set_str_hndl, tvb, offset, 1,
											ENC_LITTLE_ENDIAN);
						offset += 1;
					break;
				default:
					col_append_fstr(pinfo->cinfo, COL_INFO,
								"Unsupported or Invalid attribute type");
					break;
			}
		} else {
			proto_tree_add_item(p_tree, hf_bios_next_data_handle, tvb, offset, 4,
								ENC_LITTLE_ENDIAN);
			offset += 4;
		}
		break;
	case 0x08: // Get BIOS Attribute Current Value by Handle
		if (request) {
			proto_tree_add_item(p_tree, hf_bios_data_handle, tvb, offset, 4,
								ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(p_tree, hf_pldm_base_transferOperationFlag, tvb, offset, 1,
								ENC_LITTLE_ENDIAN);
			offset += 1;
			proto_tree_add_item(p_tree, hf_bios_attr_handle, tvb, offset, 2,
								ENC_LITTLE_ENDIAN);
		} else {
			proto_tree_add_item(p_tree, hf_bios_next_data_handle, tvb, offset, 4,
								ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(p_tree, hf_bios_transfer_flag, tvb, offset, 1,
								ENC_LITTLE_ENDIAN);
			offset += 1;
			bytes_traversed += 5;
			dissect_bios_attribute_val_table(tvb, p_tree, &offset, pinfo, bytes_traversed);
		}
		break;
	case 0x0c: // Get Date and Time
		if (!request) {
			sec = BCD44_TO_DEC(tvb_get_uint8(tvb, offset));
			min = BCD44_TO_DEC(tvb_get_uint8(tvb, offset + 1));
			hour = BCD44_TO_DEC(tvb_get_uint8(tvb, offset + 2));
			if (hour > 23 || min > 59 || sec > 59)
				return -1;
			wmem_strbuf_t *time_buf = wmem_strbuf_new(pinfo->pool, NULL);
			wmem_strbuf_append_printf(time_buf, "%02d:%02d:%02d", hour, min, sec);
			proto_tree_add_string(p_tree, hf_pldm_time, tvb, offset, 3, wmem_strbuf_finalize(time_buf));
			offset += 3;
			uint8_t day = BCD44_TO_DEC(tvb_get_uint8(tvb, offset));
			uint8_t month = BCD44_TO_DEC(tvb_get_uint8(tvb, offset + 1));
			uint16_t year = BCD44_TO_DEC(tvb_get_uint8(tvb, offset + 3)) * 100 +
							BCD44_TO_DEC(tvb_get_uint8(tvb, offset + 2));
			if (day > 31 || day < 1 || month > 12 || month < 1)
				return -1;
			wmem_strbuf_t *date_buf = wmem_strbuf_new(pinfo->pool, NULL);
			wmem_strbuf_append_printf(date_buf, "%02d/%02d/%04d", day, month, year);
			proto_tree_add_string(p_tree, hf_pldm_date, tvb, offset, 4, wmem_strbuf_finalize(date_buf));
		}
		break;
	default:
		col_append_fstr(pinfo->cinfo, COL_INFO,
						"Unsupported or Invalid PLDM command");
		break;
	}
	return tvb_captured_length(tvb);
}   

static int dissect_pldm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                void *data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "PLDM");
	col_clear(pinfo->cinfo, COL_INFO);

	tvbuff_t *next_tvb;
	unsigned len;
	uint32_t direction;
	uint32_t instID, pldm_type, offset;
	int reported_length;
	len = tvb_reported_length(tvb);
	if (len < PLDM_MIN_LENGTH) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "Packet length %u, minimum %u", len, PLDM_MIN_LENGTH);
		return tvb_captured_length(tvb);
	}
	if (tree) {
		/* First byte is the MCTP msg type, it is 01 for PLDM over MCTP */
		offset = 1;
		proto_item *ti = proto_tree_add_item(tree, proto_pldm, tvb, offset, -1, ENC_NA);
		proto_tree *pldm_tree = proto_item_add_subtree(ti, ett_pldm);

		proto_tree_add_item_ret_uint(pldm_tree, hf_pldm_msg_direction, tvb, offset, 1, ENC_LITTLE_ENDIAN, &direction);
		proto_tree_add_item(pldm_tree, hf_pldm_reserved, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item_ret_uint(pldm_tree, hf_pldm_instance_id, tvb, offset, 1, ENC_LITTLE_ENDIAN, &instID);
		offset += 1;
		proto_tree_add_item(pldm_tree, hf_pldm_header_version, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item_ret_uint(pldm_tree, hf_pldm_type, tvb, offset, 1, ENC_LITTLE_ENDIAN, &pldm_type);
		offset += 1;
		next_tvb = tvb_new_subset_remaining(tvb, offset);
		reported_length = tvb_reported_length_remaining(tvb, offset);

		/* Handle specific packet type */
		pldm_packet_data d = {direction, instID};
		if (reported_length >= 1) {
			switch (pldm_type) {
				case 0:
					dissect_base(next_tvb, pinfo, pldm_tree, &d);
					break;
				case 2:
					dissect_platform(next_tvb, pinfo, pldm_tree, &d);
					break;
				case 3:
					dissect_bios(next_tvb, pinfo, pldm_tree, (void *)&d);
					break;
				case 4:
					dissect_FRU(next_tvb, pinfo, pldm_tree, &d);
					break;
				default:
					col_append_str(pinfo->cinfo, COL_INFO, "Unsupported or Invalid PLDM type");
			}
		}
	}
	return tvb_captured_length(tvb);
}

void proto_register_pldm(void)
{
	static hf_register_info hf[] = {
		{&hf_pldm_msg_direction,
			{"PLDM Message Direction", "pldm.direction", FT_UINT8, BASE_DEC, VALS(directions),
				0xc0, NULL, HFILL}},
		{&hf_pldm_reserved,
			{"PLDM Reserved Bit", "pldm.reservedBit", FT_UINT8, BASE_DEC, NULL,
				0x20, NULL, HFILL}},
		{&hf_pldm_instance_id,
			{"PLDM Instance Id", "pldm.instanceID", FT_UINT8, BASE_DEC, NULL,
				0x1F, NULL, HFILL}},
		{&hf_pldm_header_version,
			{"PLDM Header Version", "pldm.headerVersion", FT_UINT8, BASE_DEC, NULL,
				0xC0, NULL, HFILL}},
		{&hf_pldm_type,
			{"PLDM Type", "pldm.type", FT_UINT8, BASE_HEX, VALS(pldm_types),
				0x3f, "PLDM Specification Type", HFILL}},
		{&hf_pldm_base_TID,
			{"TID Value", "pldm.base.TID", FT_UINT8, BASE_DEC, NULL,
				0x0, "Terminus ID", HFILL}},
		{&hf_pldm_base_dataTransferHandle,
			{"Data Transfer Handle", "pldm.base.dataTransferHandle", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_pldm_base_transferOperationFlag,
			{"Transfer Operation Flag", "pldm.base.transferOperationFlag", FT_UINT8, BASE_HEX, VALS(transferOperationFlags),
				0x0, NULL, HFILL}},
		{&hf_pldm_base_nextDataTransferHandle,
			{"Next Data Transfer Handle", "pldm.base.nextDataTransferHandle", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_pldm_base_transferFlag,
			{"Transfer Flag", "pldm.base.transferFlag", FT_UINT8, BASE_HEX, VALS(transferFlags),
				0x0, NULL, HFILL}},
		{&hf_pldm_base_PLDMtype,
			{"PLDM Type Requested", "pldm.base.pldmType", FT_UINT8, BASE_HEX, VALS(pldm_types),
				0x0, "Requested PLDM Specification Type", HFILL}},
		{&hf_pldm_base_typeVersion,
			{"PLDM Type Version", "pldm.base.pldmTypeVersion", FT_STRING, BASE_NONE, NULL,
				0x0, NULL, HFILL}},
		{&hf_pldm_base_typesSupported,
			{"PLDM Type Supported", "pldm.base.typeSupported", FT_UINT8, BASE_HEX, VALS(pldm_types),
				0x0, NULL, HFILL}},
		{&hf_pldm_BIOS_commands,
			{"BIOS Command", "pldm.biosCommands", FT_UINT8, BASE_HEX, VALS(pldmBIOScmd),
				0x0, "BIOS Command Supported", HFILL}},
		{&hf_pldm_FRU_commands,
			{"FRU Command", "pldm.fruCommands", FT_UINT8, BASE_HEX, VALS(pldmFruCmds),
				0x0, "FRU Command Supported", HFILL}},
		{&hf_pldm_platform_commands,
			{"Platform Command", "pldm.platformCommands", FT_UINT8, BASE_HEX, VALS(pldmPlatformCmds),
				0x0, "Platform Command Supported", HFILL}},
		{&hf_pldm_base_commands,
			{"PLDM Base Command", "pldm.baseCommands", FT_UINT8, BASE_HEX, VALS(pldmBaseCmd),
				0x0, "PLDM Messaging and Discovery Command Supported", HFILL}},
		{&hf_pldm_completion_code,
			{"Completion Code", "pldm.completionCode", FT_UINT8, BASE_DEC, VALS(completion_codes),
				0x0, NULL, HFILL}},
		/*platform*/
		{&hf_pldm_platform_completion_code,
			{"Completion Code", "pldm.completionCode", FT_UINT8, BASE_DEC, VALS(platform_completion_codes),
				0x0, NULL, HFILL}},
		{&hf_event_message_global,
			{"Event message global enable", "pldm.platform.receiver.enable", FT_UINT8, BASE_DEC, VALS(event_message_global_enable),
				0x0, NULL, HFILL}},
		{&hf_result_status,
			{"Completion Code", "pldm.status", FT_UINT8, BASE_DEC, VALS(result_status),
				0x0, NULL, HFILL}},
		{&hf_transport_protocol_type,
			{"Transport protocol", "pldm.platform.receiver.transport", FT_UINT8, BASE_DEC, VALS(transport_protocols),
				0x0, NULL, HFILL}},
		{&hf_event_receiver_addr_info,
			{"Event receiver address info", "pldm.platform.receiver.addr_info", FT_UINT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_heartbeat_timer,
			{"Heartbeat timer", "pldm.platform.receiver.timer", FT_UINT16, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_event_class,
			{"Event Class", "pldm.platform.event.class", FT_UINT8, BASE_DEC, VALS(platform_event_message_classes),
				0x0, NULL, HFILL}},
		{&hf_sensor_id,
			{"Sensor ID", "pldm.platform.event.sensor_id", FT_UINT16, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_sensor_event_class,
			{"Sensor event class", "pldm.platform.event.sensor_event_class", FT_UINT8, BASE_DEC, VALS(sensor_platform_event_message_classes),
				0x0, NULL, HFILL}},
		{&hf_pldm_platform_format_version,
			{"Format Version", "pldm.platform.event_format_version", FT_UINT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_sensor_present_op_state,
			{"Sensor present operational state", "pldm.platform.event.sensor.op_state", FT_UINT8, BASE_DEC, VALS(platform_sensor_operational_state),
				0x0,NULL, HFILL}},
		{&hf_sensor_prev_op_state,
			{"Sensor previous operational state", "pldm.platform.event.sensor.prev_op_state", FT_UINT8, BASE_DEC, VALS(platform_sensor_operational_state),
				0x0, NULL, HFILL}},
		{&hf_sensor_offset,
			{"Sensor offset", "pldm.platform.event.sensor_offset", FT_UINT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_event_state,
			{"Event state", "pldm.platform.event.state", FT_UINT8, BASE_DEC, VALS(pldm_sensor_event_states),
				0x0, NULL, HFILL}},
		{&hf_event_prev_state,
			{"Event previous state", "pldm.platform.event.prev_state", FT_UINT8, BASE_DEC, VALS(pldm_sensor_event_states),
				0x0, NULL, HFILL}},
		{&hf_sensor_data_size,
			{"Sensor data size", "pldm.platform.sensor.data_size", FT_UINT8, BASE_DEC, VALS(sensor_data_size),
				0x0, NULL, HFILL}},
		{&hf_sensor_value_u8,
			{"Sensor reading", "pldm.platform.event.sensor.data_u8", FT_UINT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_sensor_value_s8,
			{"Sensor reading", "pldm.platform.event.sensor.data_s8", FT_INT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_sensor_value_u16,
			{"Sensor reading", "pldm.platform.event.sensor.data_u16", FT_UINT16, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_sensor_value_s16,
			{"Sensor reading", "pldm.platform.event.sensor.data_s16", FT_INT16, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_sensor_value_u32,
			{"Sensor reading", "pldm.platform.event.sensor.data_u32", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_sensor_value_s32,
			{"Sensor reading", "pldm.platform.event.sensor.data_s32", FT_INT32, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_effecter_value_pnd_u8,
			{"Pending Effecter Value in uint8", "pldm.platform.effecter.pnd_val_u8", FT_UINT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_effecter_value_pnd_s8,
			{"Pending Effecter Value in sint8", "pldm.platform.effecter.pnd_val_s8", FT_INT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_effecter_value_pnd_u16,
			{"Pending Effecter Value in uint16", "pldm.platform.effecter.pnd_val_u16", FT_UINT16, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_effecter_value_pnd_s16,
			{"Pending Effecter Value in sint16", "pldm.platform.effecter.pnd_val_s16", FT_INT16, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_effecter_value_pnd_u32,
			{"Pending Effecter Value in uint32", "pldm.platform.effecter.pnd_val_u32", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_effecter_value_pnd_s32,
			{"Pending Effecter Value in sint32", "pldm.platform.effecter.pnd_val_s32", FT_INT32, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_effecter_value_pres_u8,
			{"Present Effecter Value in uint8", "pldm.platform.effecter.pres_val_u8", FT_UINT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_effecter_value_pres_s8,
			{"Present Effecter Value in sint8", "pldm.platform.effecter.pres_val_s8", FT_INT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_effecter_value_pres_u16,
			{"Present Effecter Value in uint16", "pldm.platform.effecter.pres_val_u16", FT_UINT16, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_effecter_value_pres_s16,
			{"Present Effecter Value in sint16", "pldm.platform.effecter.pres_val_s16", FT_INT16, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_effecter_value_pres_u32,
			{"Present Effecter Value in uint32", "pldm.platform.effecter.pres_val_u32", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_effecter_value_pres_s32,
			{"Present Effecter Value in sint32", "pldm.platform.effecter.pres_val_s32", FT_INT32, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_pdr_data_format,
			{"PDR Repository change data format", "pldm.platform.event.pdr.data_format", FT_UINT8, BASE_DEC, VALS(pldm_pdr_repository_chg_event_data_format),
				0x0, NULL, HFILL}},
		{&hf_pdr_num_change_recs,
			{"Number of PDR Records Changed", "pldm.platform.event.pdr_rec_change_num", FT_UINT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_pdr_repo_change_event_data_op,
			{"PDR Repository change event record - data operation", "pldm.platform.event.pdr.record.data_op", FT_UINT8, BASE_DEC, VALS(pdr_repo_chg_event_data_operation),
				0x0, NULL, HFILL}},
		{&hf_pdr_repo_change_rec_num_change_entries,
			{"PDR Repository change event record - number of change entries", "pldm.platform.event.pdr.record.num_of_changes", FT_UINT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_pdr_repo_change_event_record_pdr_type,
			{"PDR Repository change event record-PDR Type", "pldm.platform.event.pdr.record.pdr_type", FT_UINT32, BASE_DEC, VALS(platform_pdr_type),
				0x0, NULL, HFILL}},
		{&hf_pdr_repo_change_event_record_pdr_record_handle,
			{"PDR Repository change event record-PDR Record Handle", "pldm.platform.event.pdr.record.pdr_rec_handle", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_heartbeat_format_ver,
			{"Heartbeat Format Version", "pldm.platform.event.heartbeat.format_version", FT_UINT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_heartbeat_sequence_num,
			{"Heartbeat sequence number", "pldm.platform.event.heartbeat.seq", FT_UINT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_sensor_rearm,
			{"Sensor re-armed", "pldm.platform.sensor_rearm", FT_UINT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_sensor_rearm_none,
			{"No Sensor Re-armed", "pldm.platform.sensor_rearm_none", FT_UINT8, BASE_HEX, NULL,
				0x0, NULL, HFILL}},
		{&hf_pldm_sensor_reserved,
			{"PLDM Sensor Reserved Byte", "pldm.platform.sensor.reserved_byte", FT_UINT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_sensor_prev_event_state,
			{"Sensor Previous Event State", "pldm.platform.prev_event", FT_UINT8, BASE_DEC, VALS(pldm_sensor_event_states),
				0x0, NULL, HFILL}},
		{&hf_sensor_present_event_state,
			{"Sensor Present Event State", "pldm.platform.present_event", FT_UINT8, BASE_DEC, VALS(pldm_sensor_event_states),
				0x0, NULL, HFILL}},
		{&hf_sensor_event_state,
			{"Sensor Event State", "pldm.platform.event_state", FT_UINT8, BASE_DEC, VALS(pldm_sensor_event_states),
				0x0, NULL, HFILL}},
		{&hf_sensor_composite_count,
			{"Sensor Composite Count", "pldm.platform.sensor_comp_count", FT_UINT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_event_rearm,
			{"Rearm Event State", "pldm.platform.rearm_event_state", FT_UINT8, BASE_DEC, VALS(sensor_bool8),
				0x0, NULL, HFILL}},
		{&hf_sensor_event_msg_enable,
			{"Sensor Event Message Enable", "pldm.platform.sensor_event_enable", FT_UINT8, BASE_DEC, VALS(pldm_sensor_event_message_enable),
				0x0, NULL, HFILL}},
		{&hf_effecter_id,
			{"Effecter ID", "pldm.platform.effecter.id", FT_UINT16, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_effecter_count,
			{"Effecter count", "pldm.platform.effecter.count", FT_UINT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_effecter_datasize,
			{"Effecter Data Size", "pldm.platform.effecter.datasize", FT_UINT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_effecter_value_u8,
			{"Effecter Value", "pldm.platform.effecter.value_u8", FT_UINT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_effecter_value_s8,
			{"Effecter Value", "pldm.platform.effecter.value_s8", FT_INT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_effecter_value_u16,
			{"Effecter Value", "pldm.platform.effecter.value_u16", FT_UINT16, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_effecter_value_s16,
			{"Effecter Value", "pldm.platform.effecter.value_s16", FT_INT16, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_effecter_value_u32,
			{"Effecter Value", "pldm.platform.effecter.value_u32", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_effecter_value_s32,
			{"Effecter Value", "pldm.platform.effecter.value_s32", FT_INT32, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_effecter_op_state,
			{"Effecter Operational State", "pldm.platform.effecter_op_state", FT_UINT8, BASE_DEC, VALS(pldm_effecter_oper_state),
				0x0, NULL, HFILL}},
		{&hf_effecter_set_request,
			{"Effecter Set Request", "pldm.platform.effecter_set_req", FT_UINT8, BASE_DEC, VALS(pldm_effecter_state_set_request),
				0x0, NULL, HFILL}},
		{&hf_effecter_state,
			{"Effecter State", "pldm.platform.effecter_state", FT_UINT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},

		/* PDR */
		{&hf_pdr_record_handle,
			{"PDR record handle", "pldm.platform.pdr.record_handle", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_pdr_data_handle,
			{"PDR data transfer handle", "pldm.platform.pdr.data_handle", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_pdr_transfer_op_flag,
			{"PDR transfer operation flag", "pldm.platform.pdr.transfer_op_flag", FT_UINT8, BASE_DEC, VALS(transfer_op_flags),
				0x0, NULL, HFILL}},
		{&hf_pdr_req_count,
			{"PDR request count", "pldm.platform.pdr.request.count", FT_UINT16, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_pdr_record_change_num,
			{"PDR record change number", "pldm.platform.pdr.record_change_number", FT_UINT16, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_pdr_next_record_handle,
			{"PDR next record handle", "pldm.platform.pdr.next_record_handle", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_pdr_next_data_handle,
			{"PDR next data transfer handle", "pldm.platform.pdr.next_data_handle", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_pdr_transfer_flag,
			{"PDR transfer flag", "pldm.platform.pdr.transfer_flag", FT_UINT8, BASE_DEC, VALS(pdr_transfer_flags),
				0x0, NULL, HFILL}},
		{&hf_pdr_response_count,
			{"PDR response count", "pldm.platform.pdr.response.count", FT_UINT16, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_pdr_record_data,
			{"PDR Record Data Byte", "pldm.platform.pdr.record_data", FT_UINT8, BASE_HEX, NULL,
				0x0, NULL, HFILL}},
		{&hf_transfer_crc,
			{"PDR transfer CRC", "pldm.platform.pdr.crc", FT_UINT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		/*FRU*/
		{&hf_fru_completion_code,
			{"FRU completion code", "pldm.fru.completion_code", FT_UINT8, BASE_HEX, VALS(FRU_completion_code),
				0x0, NULL, HFILL}},
		{&hf_fru_major_ver,
			{"FRU Major version", "pldm.fru.ver.major", FT_UINT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_fru_minor_ver,
			{"FRU Minor version", "pldm.fru.ver.minor", FT_UINT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_fru_table_max_size,
			{"FRU Maximum table size", "pldm.fru.table.max", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_fru_table_length,
			{"FRU Table length", "pldm.fru.table.len", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_fru_num_record_identifiers,
			{"Total number of record set identifiers", "pldm.fru.num_identifiers", FT_UINT16, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_fru_num_records,
			{"Total number of records in table", "pldm.fru.table.num_records", FT_UINT16, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_fru_table_crc,
			{"FRU Table CRC", "pldm.fru.table.crc", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_fru_data_handle,
			{"FRU Data transfer handle", "pldm.fru.table.handle", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_fru_transfer_op_flag,
			{"FRU Data transfer operation flag", "pldm.fru.table.opflag", FT_UINT8, BASE_DEC, VALS(transfer_op_flags),
				0x0, NULL, HFILL}},
		{&hf_fru_next_data_handle,
			{"FRU Next data transfer handle", "pldm.fru.table.nexthandle", FT_UINT32, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_fru_transfer_flag,
			{"FRU Data transfer flag", "pldm.fru.table.flag", FT_UINT8, BASE_DEC, VALS(transferFlags),
				0x0, NULL, HFILL}},
		{&hf_fru_table_handle,
			{"FRU Record Data Handle", "pldm.fru.table_handle", FT_UINT16, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		// FRU Record fields
		{&hf_fru_record_id,
			{"FRU Record Set Identifier", "pldm.fru.record.id", FT_UINT16, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_fru_record_type,
			{"FRU Record Type", "pldm.fru.record.type", FT_UINT8, BASE_DEC, VALS(record_types),
				0x0, NULL, HFILL}},
		{&hf_fru_record_num_fields,
			{"Number of FRU fields", "pldm.fru.record.num_fields", FT_UINT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_fru_record_encoding,
			{"FRU Record Encoding", "pldm.fru.record.encoding", FT_UINT8, BASE_DEC, VALS(record_encoding),
				0x0, NULL, HFILL}},
		{&hf_fru_record_field_type,
			{"FRU Record Field Type", "pldm.fru.record.field_type", FT_UINT8, BASE_DEC, VALS(field_types_general),
				0x0, NULL, HFILL}},
		{&hf_fru_record_field_len,
			{"FRU Record Field Length", "pldm.fru.record.field_length", FT_UINT8, BASE_DEC, NULL,
				0x0, NULL, HFILL}},
		{&hf_fru_record_field_value,
			{"FRU Record Field Value", "pldm.fru.record.field_value", FT_STRING, BASE_NONE, NULL,
				0x0, NULL, HFILL}},
		{&hf_fru_record_crc,
			{"FRU Record CRC32 (Unchecked)", "pldm.fru.record.crc", FT_UINT32, BASE_HEX, NULL,
				0x0, NULL, HFILL}},
		/*BIOS*/
		{&hf_bios_data_handle,
			{"Data transfer handle", "pldm.bios.table.handle", FT_UINT32, BASE_HEX,
			NULL, 0x0, NULL, HFILL}},
		{&hf_bios_table_type,
			{"BIOS table type", "pldm.bios.table.type", FT_UINT8, BASE_HEX,
			VALS(bios_table_types), 0x0, NULL, HFILL}},
		{&hf_bios_next_data_handle,
			{"Next data transfer handle", "pldm.bios.table.nexthandle", FT_UINT32,
			BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_transfer_flag,
			{"Data transfer operation flag", "pldm.bios.table.flag", FT_UINT8,
			BASE_HEX, VALS(transferFlags), 0x0, NULL, HFILL}},
		{&hf_bios_attr_handle,
			{"Attribute handle", "pldm.bios.attr.handle", FT_UINT16, BASE_HEX, NULL,
			0x0, NULL, HFILL}},
		{&hf_bios_attr_type,
			{"Attribute type", "pldm.bios.attr.type", FT_UINT8, BASE_HEX,
			VALS(bios_attribute_type), 0x0, NULL, HFILL}},
		{&hf_bios_attr_name_handle,
			{"BIOS attribute name handle", "pldm.bios.attr.name.handle", FT_UINT16,
			BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_enumer_num_pos_values,
			{"BIOS enumeration number of possible values",
			"pldm.bios.enumer.num.pos.values", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
			HFILL}},
		{&hf_bios_enumer_pos_value_str_hndl,
			{"BIOS enumeration possible value string handle",
			"pldm.bios.enumer.pos.value.str.hndl", FT_UINT16, BASE_HEX, NULL, 0x0, NULL,
			HFILL}},
		{&hf_bios_enumer_num_default_values,
			{"BIOS enumeration number of default values",
			"pldm.bios.enumer.num.default.values", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
			HFILL}},
		{&hf_bios_enumer_default_value_str_hndl,
			{"BIOS enumeration default value string handle",
			"pldm.bios.enumer.default.value.str.hndl", FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL}},
		{&hf_bios_attr_table_pad_bytes,
			{"BIOS attribute table pad bytes", "pldm.bios.attribute.pad.bytes", FT_UINT64,
			BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_attr_table_checksum,
			{"BIOS attribute table checksum", "pldm.bios.attr.table.checksum", FT_UINT32,
			BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_str_handle,
			{"BIOS attribute string handle", "pldm.bios.str.handle", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL}},
		{&hf_bios_str_len,
			{"BIOS attribute string length", "pldm.bios.str.len", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL}},
		{&hf_bios_str,
			{"BIOS attribute string", "pldm.bios.attribute.str", FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL}},
		{&hf_bios_string_type,
			{"BIOS attribute string type", "pldm.bios.string.type", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL}},
		{&hf_bios_min_str_len,
			{"BIOS attribute min string length", "pldm.bios.min.str.len", FT_UINT16,
			BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_max_str_len,
			{"BIOS attribute max string length", "pldm.bios.max.str.len", FT_UINT16,
			BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_def_str_len,
			{"BIOS attribute default string length", "pldm.bios.def.str.len", FT_UINT16,
			BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_def_str,
			{"BIOS attribute default string", "pldm.bios.def.str", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL}},
		{&hf_bios_pass_type,
			{"BIOS attribute password type", "pldm.bios.password.type", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL}},
		{&hf_bios_min_pass_len,
			{"BIOS attribute min password length", "pldm.bios.min.password.len", FT_UINT16,
			BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_max_pass_len,
			{"BIOS attribute max password length", "pldm.bios.max.password.len", FT_UINT16,
			BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_def_pass_len,
			{"BIOS attribute default password length", "pldm.bios.def.password.len",
			FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_def_pass,
			{"BIOS attribute default password", "pldm.bios.def.password", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL}},
		{&hf_bios_int_lower_bound,
			{"BIOS attribute integer lower bound", "pldm.bios.int.lower.bound", FT_UINT64,
			BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_int_upper_bound,
			{"BIOS attribute integer upper bound", "pldm.bios.int.upper.bound", FT_UINT64,
			BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_int_scalar_inc,
			{"BIOS attribute integer scalar inc", "pldm.bios.int.scalar.inc", FT_UINT32,
			BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_int_def_val,
			{"BIOS attribute integer default value", "pldm.bios.int.def.val", FT_UINT64,
			BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_boot_config_type,
			{"BIOS boot config type", "pldm.bios.boot.config.type", FT_UINT8, BASE_HEX,
			VALS(pldm_bios_boot_config_type), 0x0, NULL, HFILL}},
		{&hf_bios_fail_through_modes,
			{"BIOS attribute suuported and ordered fail through modes",
			"pldm.bios.fail.through.modes", FT_UINT8, BASE_HEX, VALS(pldm_bios_fail_through_mode),
		0x0, NULL, HFILL}},
		{&hf_bios_min_num_boot_src,
			{"BIOS attribute minimum number of boot source settings",
			"pldm.bios.min.num.boot.src", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_max_num_boot_src,
			{"BIOS attribute maximum number of boot source settings",
			"pldm.bios.max.num.boot.src", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_pos_num_boot_src,
			{"BIOS attribute number of possible boot source settings",
			"pldm.bios.pos.num.boot.src", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_src_str_hndl,
			{"BIOS attribute possible boot source string handle",
			"pldm.bios.src.str.hndl", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_col_name_str_hndl,
			{"BIOS attribute collection name string handle",
			"pldm.bios.col.name.str.hndl", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_max_num_attr,
			{"BIOS attribute max number of attributes", "pldm.bios.max.num.attr",
			FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_col_type,
			{"BIOS attribute collection type", "pldm.bios.col.type", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL}},
		{&hf_bios_num_pos_config,
			{"BIOS attribute number of possible BIOS config", "pldm.bios.num.pos.config",
			FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_pos_config_str_hndl,
			{"BIOS attribute possible BIOS config string handle",
			"pldm.bios.pos.config.str.hndl", FT_UINT16, BASE_HEX, NULL, 0x0, NULL,
			HFILL}},
		{&hf_bios_enumer_num_cur_values,
			{"BIOS attribute enumeration number of current values",
			"pldm.bios.enumer.num.cur.values", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
			HFILL}},
		{&hf_bios_enumer_cur_value_str_hndl,
			{"BIOS attribute enumeration current value string handle",
			"pldm.bios.enumer.cur.value.str.hndl", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
			HFILL}},
		{&hf_bios_cur_str_len,
			{"BIOS attribute current string length", "pldm.bios.cur.str.len", FT_UINT16,
			BASE_DEC, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_cur_str,
			{"BIOS attribute current string", "pldm.bios.cur.str", FT_UINT64, BASE_HEX,
			NULL, 0x0, NULL, HFILL}},
		{&hf_bios_cur_pass_len,
			{"BIOS attribute current password length", "pldm.bios.cur.pass.len",
			FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_cur_pass,
			{"BIOS attribute current password", "pldm.bios.cur.pass", FT_UINT32, BASE_HEX,
			NULL, 0x0, NULL, HFILL}},
		{&hf_bios_cur_val,
			{"BIOS attribute current value", "pldm.bios.cur.val", FT_UINT64, BASE_DEC,
			NULL, 0x0, NULL, HFILL}},
		{&hf_bios_num_boot_src,
			{"BIOS attribute number of boot source settings", "pldm.bios.num.boot.src",
			FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_boot_src_str_hndl,
			{"BIOS attribute boot source setting string handle",
			"pldm.bios.boot.src.str.hndl", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_num_attr,
			{"BIOS collection number of attributes", "pldm.bios.num.attr", FT_UINT8,
			BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_attr_hndl,
			{"BIOS collection attribute handle", "pldm.bios.attr.hndl", FT_UINT16,
			BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_cur_config_set_str_hndl,
			{"BIOS cuurent config set string handle index",
			"pldm.bios.cur.config.set.str.hndl", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
			HFILL}},
		{&hf_bios_enumer_num_pen_values,
			{"BIOS attribute enumeration pending of current values",
			"pldm.bios.enumer.num.pen.values", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
			HFILL}},
		{&hf_bios_enumer_pen_value_str_hndl,
			{"BIOS attribute enumeration pending value string handle",
			"pldm.bios.enumer.pen.value.str.hndl", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
			HFILL}},
		{&hf_bios_pen_str_len,
			{"BIOS attribute pending string length", "pldm.bios.pen.str.len", FT_UINT16,
			BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_pen_str,
			{"BIOS attribute pending string", "pldm.bios.pen.str", FT_UINT64, BASE_HEX,
			NULL, 0x0, NULL, HFILL}},
		{&hf_bios_pen_pass_len,
			{"BIOS attribute pending password length", "pldm.bios.pen.pass.len",
			FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_pen_pass,
			{"BIOS attribute pending password", "pldm.bios.pen.pass", FT_UINT64, BASE_HEX,
			NULL, 0x0, NULL, HFILL}},
		{&hf_bios_pen_val,
			{"BIOS attribute pending value", "pldm.bios.pen.val", FT_UINT64, BASE_HEX,
			NULL, 0x0, NULL, HFILL}},
		{&hf_bios_num_curr_value,
			{"BIOS number of current values", "pldm.bios.number_curr_val", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL}},
		{&hf_bios_num_pen_boot_src,
			{"BIOS attribute number of pending boot source settings",
			"pldm.bios.num.pen.boot.src", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_config_set_str_hndl,
			{"BIOS config set string handle index", "pldm.bios.config.set.str.hndl",
			FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&hf_bios_enum_curr_str_hndl_idx,
			{"BIOS ENUM Current Value String Handle Index", "pldm.bios.enum.curr_str_handle_idx", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL}},
		{&hf_pldm_time,
			{"Time", "pldm.bios.time", FT_STRING, BASE_NONE, NULL, 0x0, NULL,
			HFILL}},
		{&hf_pldm_date,
			{"Date", "pldm.bios.date", FT_STRING, BASE_NONE, NULL, 0x0, NULL,
			HFILL}},
	};

	static int *ett[] = {&ett_pldm};
	proto_pldm = proto_register_protocol("PLDM Protocol", "PLDM", "pldm");
	proto_register_field_array(proto_pldm, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("pldm", dissect_pldm, proto_pldm);
}

void proto_reg_handoff_pldm(void)
{
	static dissector_handle_t pldm_handle;
	pldm_handle = create_dissector_handle(dissect_pldm, proto_pldm);
	dissector_add_uint("mctp.type", 1, pldm_handle);
}
