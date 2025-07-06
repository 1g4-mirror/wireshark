/* packet-cola2.c
 * Routines for SICK CoLA 2.0 protocol
 * Based on code from https://github.com/SICKAG/sick_scan_xd
 *
 * Copyright 2025 Michael Mann
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <epan/reassemble.h>
#include <epan/tfs.h>
#include <epan/unit_strings.h>
#include <epan/proto_data.h>
#include <wsutil/strtoi.h>
#include <wsutil/utf8_entities.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/dissectors/packet-udp.h>

void proto_register_sick_cola2(void);
void proto_reg_handoff_sick_cola2(void);

static int proto_sick_cola2;
static int proto_sick_cola2_udp;

static int hf_sick_cola2_magic_number;
static int hf_sick_cola2_length;
static int hf_sick_cola2_hub_center;
static int hf_sick_cola2_noc;
static int hf_sick_cola2_noc_request;
static int hf_sick_cola2_noc_sensor_network;
static int hf_sick_cola2_socket_index0;
static int hf_sick_cola2_session_id;
static int hf_sick_cola2_req_id;
static int hf_sick_cola2_cmd;
static int hf_sick_cola2_mode;
static int hf_sick_cola2_timeout;
static int hf_sick_cola2_client_id;
static int hf_sick_cola2_response_in;
static int hf_sick_cola2_response_to;
static int hf_sick_cola2_time;
static int hf_sick_cola2_read_int;
static int hf_sick_cola2_read_var;
static int hf_sick_cola2_read_data;
static int hf_sick_cola2_method_index;
static int hf_sick_cola2_method_name;
static int hf_sick_cola2_method_int;
static int hf_sick_cola2_method_var;
static int hf_sick_cola2_answer_value;
static int hf_sick_cola2_error;


static int hf_sick_cola2_udp_magic_number;
static int hf_sick_cola2_udp_protocol;
static int hf_sick_cola2_udp_major_ver;
static int hf_sick_cola2_udp_minor_ver;
static int hf_sick_cola2_udp_length;
static int hf_sick_cola2_udp_id;
static int hf_sick_cola2_udp_fragment_offset;
static int hf_sick_cola2_udp_header_reserved;

static int hf_sick_cola2_measurement_data;
static int hf_sick_cola2_measurement_version;
static int hf_sick_cola2_measurement_version_major;
static int hf_sick_cola2_measurement_version_minor;
static int hf_sick_cola2_measurement_version_release;
static int hf_sick_cola2_measurement_device_serial_number;
static int hf_sick_cola2_measurement_system_plug_serial_number;
static int hf_sick_cola2_measurement_channel;
static int hf_sick_cola2_measurement_reserved;
static int hf_sick_cola2_measurement_sequence_num;
static int hf_sick_cola2_measurement_scan_number;
static int hf_sick_cola2_measurement_timestamp_date;
static int hf_sick_cola2_measurement_timestamp_reserved;
static int hf_sick_cola2_measurement_timestamp_time;
static int hf_sick_cola2_measurement_gen_system_block_offset;
static int hf_sick_cola2_measurement_gen_system_block_size;
static int hf_sick_cola2_measurement_derived_values_block_offset;
static int hf_sick_cola2_measurement_derived_values_block_size;
static int hf_sick_cola2_measurement_measurement_data_block_offset;
static int hf_sick_cola2_measurement_measurement_data_block_size;
static int hf_sick_cola2_measurement_intrusion_block_offset;
static int hf_sick_cola2_measurement_intrusion_block_size;
static int hf_sick_cola2_measurement_application_io_block_offset;
static int hf_sick_cola2_measurement_application_io_block_size;

static int hf_sick_cola2_measurement_gen_system_run_mode_active;
static int hf_sick_cola2_measurement_gen_system_standby_mode_active;
static int hf_sick_cola2_measurement_gen_system_contamination_warning;
static int hf_sick_cola2_measurement_gen_system_contamination_error;
static int hf_sick_cola2_measurement_gen_system_reference_contour_status;
static int hf_sick_cola2_measurement_gen_system_reference_manipulation_status;
static int hf_sick_cola2_measurement_gen_system_byte0_reserved;
static int hf_sick_cola2_measurement_gen_system_safe_cut_off_path1;
static int hf_sick_cola2_measurement_gen_system_safe_cut_off_path2;
static int hf_sick_cola2_measurement_gen_system_safe_cut_off_path3;
static int hf_sick_cola2_measurement_gen_system_safe_cut_off_path4;
static int hf_sick_cola2_measurement_gen_system_safe_cut_off_path5;
static int hf_sick_cola2_measurement_gen_system_safe_cut_off_path6;
static int hf_sick_cola2_measurement_gen_system_safe_cut_off_path7;
static int hf_sick_cola2_measurement_gen_system_safe_cut_off_path8;
static int hf_sick_cola2_measurement_gen_system_safe_cut_off_path9;
static int hf_sick_cola2_measurement_gen_system_safe_cut_off_path10;
static int hf_sick_cola2_measurement_gen_system_safe_cut_off_path11;
static int hf_sick_cola2_measurement_gen_system_safe_cut_off_path12;
static int hf_sick_cola2_measurement_gen_system_safe_cut_off_path13;
static int hf_sick_cola2_measurement_gen_system_safe_cut_off_path14;
static int hf_sick_cola2_measurement_gen_system_safe_cut_off_path15;
static int hf_sick_cola2_measurement_gen_system_safe_cut_off_path16;
static int hf_sick_cola2_measurement_gen_system_safe_cut_off_path17;
static int hf_sick_cola2_measurement_gen_system_safe_cut_off_path18;
static int hf_sick_cola2_measurement_gen_system_safe_cut_off_path19;
static int hf_sick_cola2_measurement_gen_system_safe_cut_off_path20;
static int hf_sick_cola2_measurement_gen_system_safe_cut_off_path_reserved;
static int hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path1;
static int hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path2;
static int hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path3;
static int hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path4;
static int hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path5;
static int hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path6;
static int hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path7;
static int hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path8;
static int hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path9;
static int hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path10;
static int hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path11;
static int hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path12;
static int hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path13;
static int hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path14;
static int hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path15;
static int hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path16;
static int hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path17;
static int hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path18;
static int hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path19;
static int hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path20;
static int hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path_reserved;
static int hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path1;
static int hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path2;
static int hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path3;
static int hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path4;
static int hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path5;
static int hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path6;
static int hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path7;
static int hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path8;
static int hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path9;
static int hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path10;
static int hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path11;
static int hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path12;
static int hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path13;
static int hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path14;
static int hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path15;
static int hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path16;
static int hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path17;
static int hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path18;
static int hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path19;
static int hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path20;
static int hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path_reserved;
static int hf_sick_cola2_measurement_gen_system_safe_cut_off_path;
static int hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path;
static int hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path;
static int hf_sick_cola2_measurement_gen_system_cur_mon_case_no_table1;
static int hf_sick_cola2_measurement_gen_system_cur_mon_case_no_table2;
static int hf_sick_cola2_measurement_gen_system_cur_mon_case_no_table3;
static int hf_sick_cola2_measurement_gen_system_cur_mon_case_no_table4;
static int hf_sick_cola2_measurement_gen_system_reserved14;
static int hf_sick_cola2_measurement_gen_system_application_error;
static int hf_sick_cola2_measurement_gen_system_device_error;
static int hf_sick_cola2_measurement_gen_system_byte15_reserved;
static int hf_sick_cola2_measurement_derived_values_multiplication_factor;
static int hf_sick_cola2_measurement_derived_values_num_beams;
static int hf_sick_cola2_measurement_derived_values_scan_time;
static int hf_sick_cola2_measurement_derived_values_reserved;
static int hf_sick_cola2_measurement_derived_values_start_angle;
static int hf_sick_cola2_measurement_derived_values_ang_beam_resolution;
static int hf_sick_cola2_measurement_derived_values_interbeam_period;
static int hf_sick_cola2_measurement_measurement_data_num_beams;
static int hf_sick_cola2_measurement_measurement_data_beam_distance;
static int hf_sick_cola2_measurement_measurement_data_beam_reflectivity;
static int hf_sick_cola2_measurement_measurement_data_beam_status;
static int hf_sick_cola2_measurement_measurement_data_beam_status_valid;
static int hf_sick_cola2_measurement_measurement_data_beam_status_infinite;
static int hf_sick_cola2_measurement_measurement_data_beam_status_glare;
static int hf_sick_cola2_measurement_measurement_data_beam_status_reflector;
static int hf_sick_cola2_measurement_measurement_data_beam_status_contamination;
static int hf_sick_cola2_measurement_measurement_data_beam_status_contamination_warning;
static int hf_sick_cola2_measurement_measurement_data_beam_status_reserved;
static int hf_sick_cola2_measurement_intrusion_size;
static int hf_sick_cola2_measurement_intrusion;
static int hf_sick_cola2_measurement_intrusion_cut_off_path1;
static int hf_sick_cola2_measurement_intrusion_cut_off_path2;
static int hf_sick_cola2_measurement_intrusion_cut_off_path3;
static int hf_sick_cola2_measurement_intrusion_cut_off_path4;
static int hf_sick_cola2_measurement_intrusion_cut_off_path5;
static int hf_sick_cola2_measurement_intrusion_cut_off_path6;
static int hf_sick_cola2_measurement_intrusion_cut_off_path7;
static int hf_sick_cola2_measurement_intrusion_cut_off_path8;
static int hf_sick_cola2_measurement_intrusion_cut_off_path9;
static int hf_sick_cola2_measurement_intrusion_cut_off_path10;
static int hf_sick_cola2_measurement_intrusion_cut_off_path11;
static int hf_sick_cola2_measurement_intrusion_cut_off_path12;
static int hf_sick_cola2_measurement_intrusion_cut_off_path13;
static int hf_sick_cola2_measurement_intrusion_cut_off_path14;
static int hf_sick_cola2_measurement_intrusion_cut_off_path15;
static int hf_sick_cola2_measurement_intrusion_cut_off_path16;
static int hf_sick_cola2_measurement_intrusion_cut_off_path17;
static int hf_sick_cola2_measurement_intrusion_cut_off_path18;
static int hf_sick_cola2_measurement_intrusion_cut_off_path19;
static int hf_sick_cola2_measurement_intrusion_cut_off_path20;
static int hf_sick_cola2_measurement_intrusion_cut_off_path_reserved;
static int hf_sick_cola2_measurement_application_io_unsafe_inputs_input_source;
static int hf_sick_cola2_measurement_application_io_unsafe_inputs_flags;
static int hf_sick_cola2_measurement_application_io_reserved;
static int hf_sick_cola2_measurement_application_io_mon_case_num;
static int hf_sick_cola2_measurement_application_io_mon_case_flags;
static int hf_sick_cola2_measurement_application_lin_vel0;
static int hf_sick_cola2_measurement_application_lin_vel1;
static int hf_sick_cola2_measurement_application_lin_vel_flags;
static int hf_sick_cola2_measurement_application_lin_vel_flags_vel0_valid;
static int hf_sick_cola2_measurement_application_lin_vel_flags_vel1_valid;
static int hf_sick_cola2_measurement_application_lin_vel_flags_reserved1;
static int hf_sick_cola2_measurement_application_lin_vel_flags_vel0_transmit;
static int hf_sick_cola2_measurement_application_lin_vel_flags_vel1_transmit;
static int hf_sick_cola2_measurement_application_lin_vel_flags_reserved2;
static int hf_sick_cola2_measurement_application_sleep_mode;

static int hf_sick_cola2_measurement_fragments;
static int hf_sick_cola2_measurement_fragment;
static int hf_sick_cola2_measurement_fragment_overlap;
static int hf_sick_cola2_measurement_fragment_overlap_conflicts;
static int hf_sick_cola2_measurement_fragment_multiple_tails;
static int hf_sick_cola2_measurement_fragment_too_long_fragment;
static int hf_sick_cola2_measurement_fragment_error;
static int hf_sick_cola2_measurement_fragment_count;
static int hf_sick_cola2_measurement_reassembled_in;
static int hf_sick_cola2_measurement_reassembled_length;


static int ett_sick_cola2;
static int ett_sick_cola2_noc;
static int ett_sick_cola2_message;
static int ett_sick_cola2_command;

static int ett_sick_cola2_udp;
static int ett_sick_cola2_measurement_fragment;
static int ett_sick_cola2_measurement_fragments;
static int ett_sick_cola2_measurement_data;
static int ett_sick_cola2_measurement_data_timestamp;
static int ett_sick_cola2_measurement_gen_system;
static int ett_sick_cola2_measurement_derived_values;
static int ett_sick_cola2_measurement_measurement_data;
static int ett_sick_cola2_measurement_intrusion;
static int ett_sick_cola2_measurement_application_io;
static int ett_sick_cola2_measurement_gen_system_safe_cut_off_path;
static int ett_sick_cola2_measurement_gen_system_nonsafe_cut_off_path;
static int ett_sick_cola2_measurement_gen_system_reset_required_cut_off_path;
static int ett_sick_cola2_measurement_measurement_data_beam;
static int ett_sick_cola2_measurement_measurement_data_beam_status;
static int ett_sick_cola2_measurement_data_blocks;
static int ett_sick_cola2_measurement_intrusion_value;
static int ett_sick_cola2_measurement_application_lin_vel_flag;
static int ett_sick_cola2_measurement_application_io_unsafe_inputs;
static int ett_sick_cola2_measurement_application_io_mon_cases;
static int ett_sick_cola2_measurement_application_io_lin_vel;


static expert_field ei_sick_cola_command = EI_INIT;
static expert_field ei_sick_cola_command_parameter = EI_INIT;


static reassembly_table sick_cola2_measurement_reassembly_table;

static const fragment_items sick_cola2_measurement_frag_items = {
	/* Fragment subtrees */
	&ett_sick_cola2_measurement_fragment,
	&ett_sick_cola2_measurement_fragments,
	/* Fragment fields */
	&hf_sick_cola2_measurement_fragments,
	&hf_sick_cola2_measurement_fragment,
	&hf_sick_cola2_measurement_fragment_overlap,
	&hf_sick_cola2_measurement_fragment_overlap_conflicts,
	&hf_sick_cola2_measurement_fragment_multiple_tails,
	&hf_sick_cola2_measurement_fragment_too_long_fragment,
	&hf_sick_cola2_measurement_fragment_error,
	&hf_sick_cola2_measurement_fragment_count,
	/* Reassembled in field */
	&hf_sick_cola2_measurement_reassembled_in,
	/* Reassembled length field */
	&hf_sick_cola2_measurement_reassembled_length,
	/* Reassembled data field */
	NULL,
	/* Tag */
	"Measurement Data fragments"
};

struct sick_cola2_measurement_data {
	uint16_t conversation_id;
	bool more_frags;
};






#define SICK_COLA2_HEADER_SIZE			8
#define SICK_COLA2_MAGIC_NUMBER		0x02020202

#define SICK_COLA2_MEASUREMENT_MAGIC_NUMBER 0x4D533320		//MS3<space>

#define SICK_COLA2_REQUEST_MASK			0x80
#define SICK_COLA2_DELIMITER				0x20		//space character

#define OPEN_SESSION_COMMAND		'O'
#define CLOSE_SESSION_COMMAND		'C'
#define ERROR_RESPONSE				'F'
#define READ_COMMAND				'R'
#define WRITE_COMMAND				'W'
#define METHOD_COMMAND				'M'
#define ANSWER_RESPONSE				'A'

static const value_string cola2_command_vals[] = {
	{ ANSWER_RESPONSE,   "Answer" },
	{ CLOSE_SESSION_COMMAND,   "Close Session" },
	{ ERROR_RESPONSE, "Error" },
	{ METHOD_COMMAND,   "Method" },
	{ OPEN_SESSION_COMMAND,   "Open Session" },
	{ READ_COMMAND,   "Read" },
	{ METHOD_COMMAND,   "Write" },
	{ 0, NULL }
};

static const value_string cola2_error_vals[] = {
	{ 0x0001,   "METHODIN_ACCESSDENIED" },
	{ 0x0002,   "METHODIN_UNKNOWNINDEX" },
	{ 0x0003, "VARIABLE_UNKNOWNINDEX" },
	{ 0x0004,   "LOCALCONDITIONFAILED" },
	{ 0x0005,   "INVALID_DATA" },
	{ 0x0006,   "UNKNOWN_ERROR" },
	{ 0x0007,   "BUFFER_OVERFLOW" },
	{ 0x0008,   "BUFFER_UNDERFLOW" },
	{ 0x0009,   "ERROR_UNKNOWN_TYPE" },
	{ 0x000A,   "VARIABLE_WRITE_ACCESS_DENIED" },
	{ 0x000B,   "UNKNOWN_CMD_FOR_NAMESERVER" },
	{ 0x000C,   "UNKNOWN_COLA_COMMAND" },
	{ 0x000D,   "METHODIN_SERVER_BUSY" },
	{ 0x000E,   "FLEX_OUT_OF_BOUNDS" },
	{ 0x000F,   "EVENTREG_UNKNOWNINDEX" },
	{ 0x0010,   "COLA_A_VALUE_OVERFLOW" },
	{ 0x0011,   "COLA_A_INVALID_CHARACTER" },
	{ 0x0012,   "OSAI_NO_MESSAGE" },
	{ 0x0013,   "OSAI_NO_ANSWER_MESSAGE" },
	{ 0x0014,   "INTERNAL" },
	{ 0x0015,   "HubAddressCorrupted" },
	{ 0x0016,   "HubAddressDecoding" },
	{ 0x0017,   "HubAddressAddressExceeded" },
	{ 0x0018,   "HubAddressBlankExpected" },
	{ 0x0019,   "AsyncMethodsAreSuppressed" },
	{ 0x001A,   "Reserved" },
	{ 0x001B,   "Reserved" },
	{ 0x001C,   "Reserved" },
	{ 0x001D,   "Reserved" },
	{ 0x001E,   "Reserved" },
	{ 0x001F,   "Reserved" },
	{ 0x0020,   "ComplexArraysNotSupported" },
	{ 0x0021,   "SESSION_NORESOURCES" },
	{ 0x0022,   "SESSION_UNKNOWNID" },
	{ 0x0023,   "CANNOT_CONNECT" },
	{ 0x0024,   "InvalidPortId" },
	{ 0x0025,   "ScanAlreadyActive" },
	{ 0x0026,   "OutOfTimers" },
	{ 0x0027,   "Reserved" },
	{ 0, NULL }
};


static wmem_map_t *cola2_request_hashtable = NULL;

enum cola2_packet_type {COLA2_REQUEST_PACKET, COLA2_RESPONSE_PACKET, COLA2_CANNOT_CLASSIFY};

typedef struct cola2_request_key {
	enum cola2_packet_type requesttype;
	uint32_t session_handle;
	uint32_t request_id;
	uint32_t conversation;
} cola2_request_key_t;

typedef struct {
	uint32_t req_num;
	uint32_t rep_num;
	nstime_t req_time;
} cola2_request_info_t;

typedef struct cola2_request_val {
	wmem_tree_t *frames;
} cola2_request_val_t;

enum cola2_conv_state
{
	COLA2_CONV_WAITING_OPEN_SESSION_REQUEST = 0,
	COLA2_CONV_WAITING_OPEN_SESSION_RESPONSE,
	COLA2_CONV_SESSION_OPEN,
	COLA2_CONV_SESSION_CLOSING,
	COLA2_CONV_SESSION_CLOSED,
};

typedef struct _cola2_conv_info_t {
	enum cola2_conv_state state;
	uint32_t open_rsp_frame;
	uint32_t session_handle;
} cola2_conv_info_t;


static int
cola2_request_equal(const void *v, const void *w)
{
	const cola2_request_key_t *v1 = (const cola2_request_key_t *)v;
	const cola2_request_key_t *v2 = (const cola2_request_key_t *)w;

	if ((v1->request_id == v2->request_id) &&
		(v1->conversation == v2->conversation))
	{
		if (v1->session_handle == v2->session_handle)
			return 1;

		//OpenSession command wil have a 0 for a session handle in the request
		if ((v1->session_handle == 0) || (v2->session_handle == 0))
			return 1;
	}

	return 0;
}

static unsigned
cola2_request_hash (const void *v)
{
	const cola2_request_key_t *key = (const cola2_request_key_t *)v;
	unsigned val;

	val = (unsigned)(key->conversation * 37 + key->session_handle * 93 + key->request_id * 765);

	return val;
}

static void
cola2_add_request_response_fields(packet_info *pinfo, proto_tree *tree, cola2_request_key_t *request_key, cola2_request_info_t *request_info)
{
	if ( tree && request_info )
	{
		/* print state tracking in the tree */
		if ( request_key && request_key->requesttype == COLA2_REQUEST_PACKET )
		{
			/* This is a request */
			if (request_info->rep_num)
			{
				proto_item *it;

				it = proto_tree_add_uint(tree, hf_sick_cola2_response_in, NULL, 0, 0, request_info->rep_num);
				PROTO_ITEM_SET_GENERATED(it);
			}
		}
		else
		{
			if ( request_key && request_key->requesttype == COLA2_RESPONSE_PACKET )
			{
				/* This is a reply */
				if (request_info->req_num)
				{
					proto_item *it;
					nstime_t    ns;

					it = proto_tree_add_uint(tree, hf_sick_cola2_response_to, NULL, 0, 0, request_info->req_num);
					PROTO_ITEM_SET_GENERATED(it);

					nstime_delta(&ns, &pinfo->abs_ts, &request_info->req_time);
					it = proto_tree_add_time(tree, hf_sick_cola2_time, NULL, 0, 0, &ns);
					PROTO_ITEM_SET_GENERATED(it);
				}
			}
		}
	}
}

static cola2_request_info_t*
cola2_match_request( packet_info *pinfo, proto_tree *tree, cola2_request_key_t *request_key )
{
	cola2_request_key_t  *new_request_key;
	cola2_request_val_t  *request_val;
	cola2_request_info_t *request_info = NULL;

	request_val = (cola2_request_val_t*)wmem_map_lookup( cola2_request_hashtable, request_key );
	if (!pinfo->fd->visited)
	{
		if (request_key && request_key->requesttype == COLA2_REQUEST_PACKET )
		{
			if ( request_val == NULL )
			{
				new_request_key = (cola2_request_key_t *)wmem_memdup(wmem_file_scope(), request_key, sizeof(cola2_request_key_t));

				request_val = wmem_new(wmem_file_scope(), cola2_request_val_t);
				request_val->frames = wmem_tree_new(wmem_file_scope());

				wmem_map_insert(cola2_request_hashtable, new_request_key, request_val );
			}

			request_info = wmem_new(wmem_file_scope(), cola2_request_info_t);
			request_info->req_num = pinfo->num;
			request_info->rep_num = 0;
			request_info->req_time = pinfo->abs_ts;
			wmem_tree_insert32(request_val->frames, pinfo->num, (void *)request_info);
		}
		if ( request_val && request_key && request_key->requesttype == COLA2_RESPONSE_PACKET )
		{
			request_info = (cola2_request_info_t*)wmem_tree_lookup32_le( request_val->frames, pinfo->num );
			if ( request_info )
			{
				request_info->rep_num = pinfo->num;
			}
		}
	}
	else
	{
		if ( request_val )
			request_info = (cola2_request_info_t*)wmem_tree_lookup32_le( request_val->frames, pinfo->num );
	}

	cola2_add_request_response_fields(pinfo, tree, request_key, request_info);
	return request_info;
}

static uint8_t*
cola_get_ascii_parameter_string(tvbuff_t *tvb, wmem_allocator_t* allocator, int offset, int* new_offset)
{
	uint8_t* str_parameter;
	int parameter_end;

	parameter_end = tvb_find_uint8(tvb, offset, -1, SICK_COLA2_DELIMITER);
	if (parameter_end < 0)
	{
		*new_offset = -1;
		return NULL;
	}

	str_parameter = tvb_get_string_enc(allocator, tvb, offset, parameter_end - offset, ENC_NA | ENC_ASCII);
	*new_offset = parameter_end;
	return str_parameter;
}

static bool
cola_ascii_add_parameter_U32(proto_tree *tree, int hf_parameter, packet_info *pinfo, tvbuff_t *tvb, int* offset, char* field_name, uint32_t scale_factor)
{
	uint8_t* str_parameter;
	int parameter_end_offset;
	unsigned paramU32;

	str_parameter = cola_get_ascii_parameter_string(tvb, pinfo->pool, *offset, &parameter_end_offset);
	if (str_parameter == NULL)
	{
		expert_add_info_format(pinfo, tree, &ei_sick_cola_command_parameter, "Parse error for %s", field_name);
		return false;
	}

	if (!ws_hexstrtou32(str_parameter, NULL, &paramU32))
		return false;

	proto_tree_add_uint(tree, hf_parameter, tvb, *offset, parameter_end_offset - *offset, paramU32/scale_factor);

	*offset = parameter_end_offset+1;
	return true;
}

static bool
cola_ascii_add_parameter_REAL(proto_tree *tree, int hf_parameter, packet_info *pinfo, tvbuff_t *tvb, int* offset, char* field_name)
{
	uint8_t* str_parameter;
	int parameter_end_offset;
	unsigned paramU32;
	float paramFloat;

	str_parameter = cola_get_ascii_parameter_string(tvb, pinfo->pool, *offset, &parameter_end_offset);
	if (str_parameter == NULL)
	{
		expert_add_info_format(pinfo, tree, &ei_sick_cola_command_parameter, "Parse error for %s", field_name);
		return false;
	}

	if (!ws_hexstrtou32(str_parameter, NULL, &paramU32))
		return false;

	memcpy(&paramFloat, &paramU32, 4);
	proto_tree_add_float(tree, hf_parameter, tvb, *offset, parameter_end_offset - *offset, paramFloat);

	*offset = parameter_end_offset+1;
	return true;
}

static bool
cola_ascii_add_parameter_I32(proto_tree *tree, int hf_parameter, packet_info *pinfo, tvbuff_t *tvb, int* offset, char* field_name, int scale_factor)
{
	uint8_t* str_parameter;
	int parameter_end_offset;
	unsigned paramU32;

	str_parameter = cola_get_ascii_parameter_string(tvb, pinfo->pool, *offset, &parameter_end_offset);
	if (str_parameter == NULL)
	{
		expert_add_info_format(pinfo, tree, &ei_sick_cola_command_parameter, "Parse error for %s", field_name);
		return false;
	}

	if (!ws_hexstrtou32(str_parameter, NULL, &paramU32))
		return false;

	proto_tree_add_int(tree, hf_parameter, tvb, *offset, parameter_end_offset - *offset, ((int32_t)paramU32)/scale_factor);

	*offset = parameter_end_offset+1;
	return true;
}

static bool
cola_ascii_add_parameter_I16(proto_tree *tree, int hf_parameter, packet_info *pinfo, tvbuff_t *tvb, int* offset, char* field_name)
{
	uint8_t* str_parameter;
	int parameter_end_offset;
	uint16_t paramU16;

	str_parameter = cola_get_ascii_parameter_string(tvb, pinfo->pool, *offset, &parameter_end_offset);
	if (str_parameter == NULL)
	{
		expert_add_info_format(pinfo, tree, &ei_sick_cola_command_parameter, "Parse error for %s", field_name);
		return false;
	}

	if (!ws_hexstrtou16(str_parameter, NULL, &paramU16))
		return false;

	proto_tree_add_int(tree, hf_parameter, tvb, *offset, parameter_end_offset - *offset, (int16_t)paramU16);

	*offset = parameter_end_offset+1;
	return true;
}
static bool
cola_ascii_add_parameter_2U8(proto_tree *tree, int hf_parameter, packet_info *pinfo, tvbuff_t *tvb, int* offset, char* field_name)
{
	uint8_t* str_parameter;
	int parameter_end_offset, start_offset = *offset;
	uint16_t param1, param2, paramU16;

	str_parameter = cola_get_ascii_parameter_string(tvb, pinfo->pool, *offset, &parameter_end_offset);
	if (str_parameter == NULL)
	{
		expert_add_info_format(pinfo, tree, &ei_sick_cola_command_parameter, "Parse error for %s", field_name);
		return false;
	}

	if (!ws_hexstrtou16(str_parameter, NULL, &param1))
		return false;

	*offset = parameter_end_offset+1;
	str_parameter = cola_get_ascii_parameter_string(tvb, pinfo->pool, *offset, &parameter_end_offset);
	if (str_parameter == NULL)
	{
		expert_add_info_format(pinfo, tree, &ei_sick_cola_command_parameter, "Parse error for %s", field_name);
		return false;
	}

	if (!ws_hexstrtou16(str_parameter, NULL, &param2))
		return false;

	paramU16 = ((param1 << 8) & 0xFF00) | (param2 & 0x00FF);

	proto_tree_add_uint(tree, hf_parameter, tvb, *offset, parameter_end_offset - start_offset, paramU16);

	*offset = parameter_end_offset+1;
	return true;
}

static bool
cola_ascii_add_parameter_string(proto_tree *tree, int hf_parameter, packet_info *pinfo, tvbuff_t *tvb, int* offset, char* field_name)
{
	uint8_t* str_parameter;
	int parameter_end_offset;

	str_parameter = cola_get_ascii_parameter_string(tvb, pinfo->pool, *offset, &parameter_end_offset);
	if (str_parameter == NULL)
	{
		expert_add_info_format(pinfo, tree, &ei_sick_cola_command_parameter, "Parse error for %s", field_name);
		return false;
	}

	proto_tree_add_string(tree, hf_parameter, tvb, *offset, parameter_end_offset - *offset, str_parameter);

	*offset = parameter_end_offset+1;
	return true;
}


static int
diplay_timestamp_field(proto_tree *tree, tvbuff_t *tvb, int offset, int hf_field, bool binary)
{
	int time_offset = offset;
	struct tm time_info;
	time_t time_info_seconds;
	nstime_t ns_time_info;

	if (binary)
	{
		time_info.tm_year = tvb_get_ntohs(tvb, time_offset)-1900;
		time_offset += 2;
		time_info.tm_mon = tvb_get_uint8(tvb, time_offset)-1;
		time_offset += 1;
		time_info.tm_mday = tvb_get_uint8(tvb, time_offset);
		time_offset += 1;
		time_info.tm_hour = tvb_get_uint8(tvb, time_offset);
		time_offset += 1;
		time_info.tm_min = tvb_get_uint8(tvb, time_offset);
		time_offset += 1;
		time_info.tm_sec = tvb_get_uint8(tvb, time_offset);
		time_offset += 1;

		time_info_seconds = mktime(&time_info);
		ns_time_info.secs = time_info_seconds;
		ns_time_info.nsecs = tvb_get_ntohl(tvb, time_offset)*1000;
		proto_tree_add_time(tree, hf_field, tvb, offset, 11, &ns_time_info);
		offset += 11;
	}

	return offset;
}

static unsigned
get_sick_cola2_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	uint32_t len = 0;

	len = tvb_get_ntohl(tvb, offset+4);

	return len+SICK_COLA2_HEADER_SIZE;
}

static int
dissect_sick_cola2_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree      *cola2_tree, *noc_tree, *message_tree, *command_tree;
	proto_item      *ti, *command_item, *noc_item, *message_item;
	int				offset = 0;
	uint32_t			length, noc, command, mode;
	cola2_request_key_t request_key;
	conversation_t     *conversation;
	cola2_conv_info_t  *cola2_info;
	bool		open_session_msg_rqst = false;

	if (tvb_get_ntohl(tvb, offset) != SICK_COLA2_MAGIC_NUMBER)
	{
		//not our packet
		return 0;
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CoLa 2.0");
	col_clear(pinfo->cinfo, COL_INFO);

	/*
	* We need to track some state for this protocol on a per conversation
	* basis so we can do neat things like request/response tracking
	*/
	conversation = find_or_create_conversation(pinfo);
	cola2_info = (cola2_conv_info_t*)conversation_get_proto_data(conversation, proto_sick_cola2);
	if (cola2_info == NULL)
	{
		if (!pinfo->fd->visited)
		{
			cola2_info = wmem_new0(wmem_file_scope(), cola2_conv_info_t);
			//Currently redundant, but being explicit
			cola2_info->state = COLA2_CONV_WAITING_OPEN_SESSION_REQUEST;

                        conversation_add_proto_data(conversation, proto_sick_cola2, cola2_info);
		}
		else
		{
			//This shouldn't happen, but just so the data isn't NULL
			cola2_info = wmem_new0(pinfo->pool, cola2_conv_info_t);
		}
	}


	ti = proto_tree_add_item(tree, proto_sick_cola2, tvb, offset, -1, ENC_NA);
	cola2_tree = proto_item_add_subtree(ti, ett_sick_cola2);
	message_tree = proto_tree_add_subtree(cola2_tree, tvb, offset, -1, ett_sick_cola2_message, &message_item, "Message");

	proto_tree_add_item(message_tree, hf_sick_cola2_magic_number, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item_ret_uint(message_tree, hf_sick_cola2_length, tvb, offset, 4, ENC_BIG_ENDIAN, &length);
	offset += 4;

	proto_tree_add_item(message_tree, hf_sick_cola2_hub_center, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	noc_item = proto_tree_add_item_ret_uint(message_tree, hf_sick_cola2_noc, tvb, offset, 1, ENC_BIG_ENDIAN, &noc);
	noc_tree = proto_item_add_subtree(noc_item, ett_sick_cola2_noc);
	proto_tree_add_item(noc_tree, hf_sick_cola2_noc_request, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(noc_tree, hf_sick_cola2_noc_sensor_network, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	if (noc != 0)
	{
		proto_tree_add_item(message_tree, hf_sick_cola2_socket_index0, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
	}
	proto_item_set_len(message_item, offset);

	command_tree = proto_tree_add_subtree(cola2_tree, tvb, offset, -1, ett_sick_cola2_command, NULL, "Command");

	proto_tree_add_item_ret_uint(command_tree, hf_sick_cola2_session_id, tvb, offset, 4, ENC_BIG_ENDIAN, &request_key.session_handle);
	offset += 4;

	proto_tree_add_item_ret_uint(command_tree, hf_sick_cola2_req_id, tvb, offset, 2, ENC_BIG_ENDIAN, &request_key.request_id);
	offset += 2;

	command_item = proto_tree_add_item_ret_uint(command_tree, hf_sick_cola2_cmd, tvb, offset, 1, ENC_BIG_ENDIAN, &command);
	col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(command, cola2_command_vals, "Unknown Command"));
	offset += 1;

	proto_tree_add_item_ret_uint(command_tree, hf_sick_cola2_mode, tvb, offset, 1, ENC_BIG_ENDIAN, &mode);
	offset += 1;

	request_key.conversation = conversation->conv_index;
	request_key.requesttype = COLA2_CANNOT_CLASSIFY;
	switch (command)
	{
	case OPEN_SESSION_COMMAND:
		switch (mode)
		{
		case 'x':
			open_session_msg_rqst = true;
			request_key.requesttype = COLA2_REQUEST_PACKET;
			col_append_str(pinfo->cinfo, COL_INFO, " (Request)");
			if (!pinfo->fd->visited)
			{
				cola2_info->state = COLA2_CONV_WAITING_OPEN_SESSION_RESPONSE;
			}
			else
			{
				/******************************************************************************************************************
				 * Need to do special handling of request/response because Open Session request doesn't include the session ID.
				 * It gets populated in the response, so the request data has to be filled in the next pass over the packets
				 ******************************************************************************************************************/
				request_key.session_handle = cola2_info->session_handle;

				//Ensure the request has been added
				cola2_request_val_t  *request_val = (cola2_request_val_t*)wmem_map_lookup( cola2_request_hashtable, &request_key);
				if (request_val == NULL)
				{
					request_val = wmem_new(wmem_file_scope(), cola2_request_val_t);
					request_val->frames = wmem_tree_new(wmem_file_scope());

					wmem_map_insert(cola2_request_hashtable, wmem_memdup(wmem_file_scope(), &request_key, sizeof(cola2_request_key_t)), request_val );
				}

				//Only add the request once
				cola2_request_info_t *request_info = wmem_tree_lookup32(request_val->frames, pinfo->num);
				if (request_info == NULL)
				{
					request_info = wmem_new(wmem_file_scope(), cola2_request_info_t);
					request_info->req_num = pinfo->num;
					request_info->rep_num = cola2_info->open_rsp_frame;
					request_info->req_time = pinfo->abs_ts;
					wmem_tree_insert32(request_val->frames, pinfo->num, (void *)request_info);
				}


				cola2_add_request_response_fields(pinfo, cola2_tree, &request_key, request_info);
			}

			proto_tree_add_item(command_tree, hf_sick_cola2_timeout, tvb, offset, 1, ENC_NA);
			offset += 1;
			proto_tree_add_item(command_tree, hf_sick_cola2_client_id, tvb, offset, 2, ENC_NA|ENC_ASCII);
			break;
		case 'A':
			request_key.requesttype = COLA2_RESPONSE_PACKET;
			col_append_str(pinfo->cinfo, COL_INFO, " (Response)");
			if (!pinfo->fd->visited)
			{
				cola2_info->state = COLA2_CONV_SESSION_OPEN;
				//Save the session handle for the open session request so request/response tracking can work for it
				cola2_info->session_handle = request_key.session_handle;
				cola2_info->open_rsp_frame = pinfo->num;
			}
			break;
		}
		break;
	case CLOSE_SESSION_COMMAND:
		switch (mode)
		{
		case 'x':
			request_key.requesttype = COLA2_REQUEST_PACKET;
			col_append_str(pinfo->cinfo, COL_INFO, " (Request)");
			if (!pinfo->fd->visited)
			{
				cola2_info->state = COLA2_CONV_SESSION_CLOSING;
			}
			break;
		case 'A':
			request_key.requesttype = COLA2_RESPONSE_PACKET;
			col_append_str(pinfo->cinfo, COL_INFO, " (Response)");
			if (!pinfo->fd->visited)
			{
				cola2_info->state = COLA2_CONV_SESSION_CLOSED;
			}
			break;
		}
		break;
	case READ_COMMAND:
		switch (mode)
		{
		case 'I':
		case 'N':
			request_key.requesttype = COLA2_REQUEST_PACKET;
			col_append_str(pinfo->cinfo, COL_INFO, " (Request)");

			if (mode == 'I')
			{
				proto_tree_add_item(command_tree, hf_sick_cola2_read_int, tvb, offset, 2, ENC_LITTLE_ENDIAN);
				offset += 2;
			}
			else
			{
				proto_tree_add_item(command_tree, hf_sick_cola2_read_var, tvb, offset, -1, ENC_NA|ENC_ASCII);
				offset = tvb_reported_length(tvb);
			}
			break;
		case 'A':
			request_key.requesttype = COLA2_RESPONSE_PACKET;
			col_append_str(pinfo->cinfo, COL_INFO, " (Response)");

			//TODO: Determine if request is integer or variable
			proto_tree_add_item(command_tree, hf_sick_cola2_read_int, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
			proto_tree_add_item(command_tree, hf_sick_cola2_read_data, tvb, offset, -1, ENC_NA);
			offset = tvb_reported_length(tvb);
			break;
		}
		break;
	case WRITE_COMMAND:
		break;
	case METHOD_COMMAND:
		switch (mode)
		{
		case 'I':
		case 'N':
			request_key.requesttype = COLA2_REQUEST_PACKET;
			col_append_str(pinfo->cinfo, COL_INFO, " (Request)");

			if (mode == 'I')
			{
				proto_tree_add_item(command_tree, hf_sick_cola2_method_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
				offset += 2;
				proto_tree_add_item(command_tree, hf_sick_cola2_method_int, tvb, offset, 2, ENC_LITTLE_ENDIAN);
				offset += 2;
			}
			else
			{
				//TODO: Find method name length
				proto_tree_add_item(command_tree, hf_sick_cola2_method_name, tvb, offset, -1, ENC_NA | ENC_ASCII);
				offset = tvb_reported_length(tvb);
				proto_tree_add_item(command_tree, hf_sick_cola2_method_var, tvb, offset, -1, ENC_NA | ENC_ASCII);
				offset = tvb_reported_length(tvb);
			}
			break;
		}
		break;
	case ANSWER_RESPONSE:
		proto_tree_add_item(command_tree, hf_sick_cola2_method_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(command_tree, hf_sick_cola2_answer_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		break;
	case ERROR_RESPONSE:
		proto_tree_add_item(command_tree, hf_sick_cola2_error, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		break;
	default:
		expert_add_info(pinfo, command_item, &ei_sick_cola_command);
		break;
	}

	//Open session requests have special handling
	if (!open_session_msg_rqst)
		cola2_match_request(pinfo, cola2_tree, &request_key);

	return tvb_captured_length(tvb);
}


static int
dissect_sick_cola2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	tcp_dissect_pdus(tvb, pinfo, tree, true, SICK_COLA2_HEADER_SIZE, get_sick_cola2_pdu_len, dissect_sick_cola2_pdu, data);
	return tvb_captured_length(tvb);
}

static bool
dissect_sick_cola2_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	if (tvb_captured_length(tvb) >= 4) { /* check of data is big enough for base header. */
		uint32_t magic_number = tvb_get_ntohl(tvb, 0);

		if (magic_number == SICK_COLA2_MAGIC_NUMBER)
		{
			dissect_sick_cola2(tvb, pinfo, tree, data);
			return true;
		}
	}
	return false;
}

static int
dissect_measurement_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t identifier)
{
	proto_tree      *measurement_tree, *timestamp_tree, *block_tree;
	proto_tree		*gen_system_tree, *derived_values_tree, *measurement_data_tree, *intrusion_tree, *application_io_tree;
	proto_item      *ti, *measurement_data_item;
	int				offset = 0;
	uint32_t			seq_num, scan_num;
	uint32_t			gen_system_block_offset, derived_values_block_offset, measurement_data_block_offset, intrusion_block_offset, application_io_block_offset;
	uint32_t			gen_system_block_size, derived_values_block_size, measurement_data_block_size, intrusion_block_size, application_io_block_size;

	ti = proto_tree_add_item(tree, hf_sick_cola2_measurement_data, tvb, offset, -1, ENC_NA);
	measurement_tree = proto_item_add_subtree(ti, ett_sick_cola2_measurement_data);

	proto_tree_add_item(measurement_tree, hf_sick_cola2_measurement_version, tvb, offset, 1, ENC_NA);
	offset += 1;
	proto_tree_add_item(measurement_tree, hf_sick_cola2_measurement_version_major, tvb, offset, 1, ENC_NA);
	offset += 1;
	proto_tree_add_item(measurement_tree, hf_sick_cola2_measurement_version_minor, tvb, offset, 1, ENC_NA);
	offset += 1;
	proto_tree_add_item(measurement_tree, hf_sick_cola2_measurement_version_release, tvb, offset, 1, ENC_NA);
	offset += 1;
	proto_tree_add_item(measurement_tree, hf_sick_cola2_measurement_device_serial_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;
	proto_tree_add_item(measurement_tree, hf_sick_cola2_measurement_system_plug_serial_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;
	proto_tree_add_item(measurement_tree, hf_sick_cola2_measurement_channel, tvb, offset, 1, ENC_NA);
	offset += 1;
	proto_tree_add_item(measurement_tree, hf_sick_cola2_measurement_reserved, tvb, offset, 3, ENC_NA);
	offset += 3;
	proto_tree_add_item_ret_uint(measurement_tree, hf_sick_cola2_measurement_sequence_num, tvb, offset, 4, ENC_LITTLE_ENDIAN, &seq_num);
	offset += 4;
	proto_tree_add_item_ret_uint(measurement_tree, hf_sick_cola2_measurement_scan_number, tvb, offset, 4, ENC_LITTLE_ENDIAN, &scan_num);
	offset += 4;

	col_add_fstr(pinfo->cinfo, COL_INFO, "ID %u Measurement data: SeqNo=%u, ScanNumber=%u", identifier, seq_num, scan_num);

	timestamp_tree = proto_tree_add_subtree(measurement_tree, tvb, offset, 8, ett_sick_cola2_measurement_data_timestamp, NULL, "Timestamp");
	proto_tree_add_item(timestamp_tree, hf_sick_cola2_measurement_timestamp_date, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(timestamp_tree, hf_sick_cola2_measurement_timestamp_reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(timestamp_tree, hf_sick_cola2_measurement_timestamp_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	//block offsets
	block_tree = proto_tree_add_subtree(measurement_tree, tvb, offset, 20, ett_sick_cola2_measurement_data_blocks, NULL, "Block Offsets");

	proto_tree_add_item_ret_uint(block_tree, hf_sick_cola2_measurement_gen_system_block_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN, &gen_system_block_offset);
	offset += 2;
	proto_tree_add_item_ret_uint(block_tree, hf_sick_cola2_measurement_gen_system_block_size, tvb, offset, 2, ENC_LITTLE_ENDIAN, &gen_system_block_size);
	offset += 2;
	proto_tree_add_item_ret_uint(block_tree, hf_sick_cola2_measurement_derived_values_block_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN, &derived_values_block_offset);
	offset += 2;
	proto_tree_add_item_ret_uint(block_tree, hf_sick_cola2_measurement_derived_values_block_size, tvb, offset, 2, ENC_LITTLE_ENDIAN, &derived_values_block_size);
	offset += 2;
	proto_tree_add_item_ret_uint(block_tree, hf_sick_cola2_measurement_measurement_data_block_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN, &measurement_data_block_offset);
	offset += 2;
	proto_tree_add_item_ret_uint(block_tree, hf_sick_cola2_measurement_measurement_data_block_size, tvb, offset, 2, ENC_LITTLE_ENDIAN, &measurement_data_block_size);
	offset += 2;
	proto_tree_add_item_ret_uint(block_tree, hf_sick_cola2_measurement_intrusion_block_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN, &intrusion_block_offset);
	offset += 2;
	proto_tree_add_item_ret_uint(block_tree, hf_sick_cola2_measurement_intrusion_block_size, tvb, offset, 2, ENC_LITTLE_ENDIAN, &intrusion_block_size);
	offset += 2;
	proto_tree_add_item_ret_uint(block_tree, hf_sick_cola2_measurement_application_io_block_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN, &application_io_block_offset);
	offset += 2;
	proto_tree_add_item_ret_uint(block_tree, hf_sick_cola2_measurement_application_io_block_size, tvb, offset, 2, ENC_LITTLE_ENDIAN, &application_io_block_size);
	offset += 2;

	if (gen_system_block_size > 0)
	{
		static int* const byte0[] = {
			&hf_sick_cola2_measurement_gen_system_run_mode_active,
			&hf_sick_cola2_measurement_gen_system_standby_mode_active,
			&hf_sick_cola2_measurement_gen_system_contamination_warning,
			&hf_sick_cola2_measurement_gen_system_contamination_error,
			&hf_sick_cola2_measurement_gen_system_reference_contour_status,
			&hf_sick_cola2_measurement_gen_system_reference_manipulation_status,
			&hf_sick_cola2_measurement_gen_system_byte0_reserved,
			NULL
		};

		static int* const gen_system_safe_cut_off_path[] = {
			&hf_sick_cola2_measurement_gen_system_safe_cut_off_path1,
			&hf_sick_cola2_measurement_gen_system_safe_cut_off_path2,
			&hf_sick_cola2_measurement_gen_system_safe_cut_off_path3,
			&hf_sick_cola2_measurement_gen_system_safe_cut_off_path4,
			&hf_sick_cola2_measurement_gen_system_safe_cut_off_path5,
			&hf_sick_cola2_measurement_gen_system_safe_cut_off_path6,
			&hf_sick_cola2_measurement_gen_system_safe_cut_off_path7,
			&hf_sick_cola2_measurement_gen_system_safe_cut_off_path8,
			&hf_sick_cola2_measurement_gen_system_safe_cut_off_path9,
			&hf_sick_cola2_measurement_gen_system_safe_cut_off_path10,
			&hf_sick_cola2_measurement_gen_system_safe_cut_off_path11,
			&hf_sick_cola2_measurement_gen_system_safe_cut_off_path12,
			&hf_sick_cola2_measurement_gen_system_safe_cut_off_path13,
			&hf_sick_cola2_measurement_gen_system_safe_cut_off_path14,
			&hf_sick_cola2_measurement_gen_system_safe_cut_off_path15,
			&hf_sick_cola2_measurement_gen_system_safe_cut_off_path16,
			&hf_sick_cola2_measurement_gen_system_safe_cut_off_path17,
			&hf_sick_cola2_measurement_gen_system_safe_cut_off_path18,
			&hf_sick_cola2_measurement_gen_system_safe_cut_off_path19,
			&hf_sick_cola2_measurement_gen_system_safe_cut_off_path20,
			&hf_sick_cola2_measurement_gen_system_safe_cut_off_path_reserved,
			NULL
		};

		static int* const gen_system_nonsafe_cut_off_path[] = {
			&hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path1,
			&hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path2,
			&hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path3,
			&hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path4,
			&hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path5,
			&hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path6,
			&hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path7,
			&hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path8,
			&hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path9,
			&hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path10,
			&hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path11,
			&hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path12,
			&hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path13,
			&hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path14,
			&hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path15,
			&hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path16,
			&hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path17,
			&hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path18,
			&hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path19,
			&hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path20,
			&hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path_reserved,
			NULL
		};

		static int* const gen_system_reset_required_cut_off_path[] = {
			&hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path1,
			&hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path2,
			&hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path3,
			&hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path4,
			&hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path5,
			&hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path6,
			&hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path7,
			&hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path8,
			&hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path9,
			&hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path10,
			&hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path11,
			&hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path12,
			&hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path13,
			&hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path14,
			&hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path15,
			&hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path16,
			&hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path17,
			&hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path18,
			&hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path19,
			&hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path20,
			&hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path_reserved,
			NULL
		};

		static int* const byte15[] = {
			&hf_sick_cola2_measurement_gen_system_application_error,
			&hf_sick_cola2_measurement_gen_system_device_error,
			&hf_sick_cola2_measurement_gen_system_byte15_reserved,
			NULL
		};

		offset = gen_system_block_offset;
		gen_system_tree = proto_tree_add_subtree(measurement_tree, tvb, offset, gen_system_block_size, ett_sick_cola2_measurement_gen_system, NULL, "General System State Block");

		proto_tree_add_bitmask_list(gen_system_tree, tvb, offset, 1, byte0, ENC_NA);
		offset += 1;
		proto_tree_add_bitmask(gen_system_tree, tvb, offset, hf_sick_cola2_measurement_gen_system_safe_cut_off_path, ett_sick_cola2_measurement_gen_system_safe_cut_off_path, gen_system_safe_cut_off_path, ENC_LITTLE_ENDIAN);
		offset += 3;
		proto_tree_add_bitmask(gen_system_tree, tvb, offset, hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path, ett_sick_cola2_measurement_gen_system_nonsafe_cut_off_path, gen_system_nonsafe_cut_off_path, ENC_LITTLE_ENDIAN);
		offset += 3;
		proto_tree_add_bitmask(gen_system_tree, tvb, offset, hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path, ett_sick_cola2_measurement_gen_system_reset_required_cut_off_path, gen_system_reset_required_cut_off_path, ENC_LITTLE_ENDIAN);
		offset += 3;

		proto_tree_add_item(gen_system_tree, hf_sick_cola2_measurement_gen_system_cur_mon_case_no_table1, tvb, offset, 1, ENC_NA);
		offset += 1;
		proto_tree_add_item(gen_system_tree, hf_sick_cola2_measurement_gen_system_cur_mon_case_no_table2, tvb, offset, 1, ENC_NA);
		offset += 1;
		proto_tree_add_item(gen_system_tree, hf_sick_cola2_measurement_gen_system_cur_mon_case_no_table3, tvb, offset, 1, ENC_NA);
		offset += 1;
		proto_tree_add_item(gen_system_tree, hf_sick_cola2_measurement_gen_system_cur_mon_case_no_table4, tvb, offset, 1, ENC_NA);
		offset += 1;
		proto_tree_add_item(gen_system_tree, hf_sick_cola2_measurement_gen_system_reserved14, tvb, offset, 1, ENC_NA);
		offset += 1;
		proto_tree_add_bitmask_list(gen_system_tree, tvb, offset, 1, byte15, ENC_NA);
	}

	if (derived_values_block_offset > 0)
	{
		int value;
		offset = derived_values_block_offset;
		derived_values_tree = proto_tree_add_subtree(measurement_tree, tvb, offset, derived_values_block_size, ett_sick_cola2_measurement_derived_values, NULL, "Derived Values Block");

		proto_tree_add_item(derived_values_tree, hf_sick_cola2_measurement_derived_values_multiplication_factor, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(derived_values_tree, hf_sick_cola2_measurement_derived_values_num_beams, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(derived_values_tree, hf_sick_cola2_measurement_derived_values_scan_time, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(derived_values_tree, hf_sick_cola2_measurement_derived_values_reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		value = (int)tvb_get_letohl(tvb, offset);
		proto_tree_add_float(derived_values_tree, hf_sick_cola2_measurement_derived_values_start_angle, tvb, offset, 4, value/4194304.0f);
		offset += 4;
		value = (int)tvb_get_letohl(tvb, offset);
		proto_tree_add_float(derived_values_tree, hf_sick_cola2_measurement_derived_values_ang_beam_resolution, tvb, offset, 4, value/4194304.0f);
		offset += 4;
		proto_tree_add_item(derived_values_tree, hf_sick_cola2_measurement_derived_values_interbeam_period, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(derived_values_tree, hf_sick_cola2_measurement_derived_values_reserved, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	}

	if (measurement_data_block_offset > 0)
	{
		static int* const beam_status[] = {
			&hf_sick_cola2_measurement_measurement_data_beam_status_valid,
			&hf_sick_cola2_measurement_measurement_data_beam_status_infinite,
			&hf_sick_cola2_measurement_measurement_data_beam_status_glare,
			&hf_sick_cola2_measurement_measurement_data_beam_status_reflector,
			&hf_sick_cola2_measurement_measurement_data_beam_status_contamination,
			&hf_sick_cola2_measurement_measurement_data_beam_status_contamination_warning,
			&hf_sick_cola2_measurement_measurement_data_beam_status_reserved,
			NULL
		};

		uint32_t num_beams;
		offset = measurement_data_block_offset;
		measurement_data_tree = proto_tree_add_subtree(measurement_tree, tvb, offset, measurement_data_block_size, ett_sick_cola2_measurement_measurement_data, &measurement_data_item, "Measurement Data Block");

		proto_tree_add_item_ret_uint(measurement_data_tree, hf_sick_cola2_measurement_measurement_data_num_beams, tvb, offset, 4, ENC_LITTLE_ENDIAN, &num_beams);
		proto_item_append_text(measurement_data_item, " (%u beams)", num_beams);
		offset += 4;
		for (unsigned b = 0; b < num_beams; b++)
		{
			proto_tree* beam_tree = proto_tree_add_subtree_format(measurement_data_tree, tvb, offset, 4, ett_sick_cola2_measurement_measurement_data_beam, NULL, "Beam #%u", b);
			proto_tree_add_item(beam_tree, hf_sick_cola2_measurement_measurement_data_beam_distance, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
			proto_tree_add_item(beam_tree, hf_sick_cola2_measurement_measurement_data_beam_reflectivity, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
			proto_tree_add_bitmask(beam_tree, tvb, offset, hf_sick_cola2_measurement_measurement_data_beam_status, ett_sick_cola2_measurement_measurement_data_beam_status, beam_status, ENC_LITTLE_ENDIAN);
		}

	}

	if (intrusion_block_offset > 0)
	{
		uint32_t num_intrusions, intrusion_value;
		proto_tree* intrusion_value_tree;
		proto_item* intrusion_item;
		static int* const intrusion_cut_off_path[] = {
			&hf_sick_cola2_measurement_intrusion_cut_off_path1,
			&hf_sick_cola2_measurement_intrusion_cut_off_path2,
			&hf_sick_cola2_measurement_intrusion_cut_off_path3,
			&hf_sick_cola2_measurement_intrusion_cut_off_path4,
			&hf_sick_cola2_measurement_intrusion_cut_off_path5,
			&hf_sick_cola2_measurement_intrusion_cut_off_path6,
			&hf_sick_cola2_measurement_intrusion_cut_off_path7,
			&hf_sick_cola2_measurement_intrusion_cut_off_path8,
			&hf_sick_cola2_measurement_intrusion_cut_off_path9,
			&hf_sick_cola2_measurement_intrusion_cut_off_path10,
			&hf_sick_cola2_measurement_intrusion_cut_off_path11,
			&hf_sick_cola2_measurement_intrusion_cut_off_path12,
			&hf_sick_cola2_measurement_intrusion_cut_off_path13,
			&hf_sick_cola2_measurement_intrusion_cut_off_path14,
			&hf_sick_cola2_measurement_intrusion_cut_off_path15,
			&hf_sick_cola2_measurement_intrusion_cut_off_path16,
			&hf_sick_cola2_measurement_intrusion_cut_off_path17,
			&hf_sick_cola2_measurement_intrusion_cut_off_path18,
			&hf_sick_cola2_measurement_intrusion_cut_off_path19,
			&hf_sick_cola2_measurement_intrusion_cut_off_path20,
			&hf_sick_cola2_measurement_intrusion_cut_off_path_reserved,
			NULL
		};

		offset = intrusion_block_offset;
		intrusion_tree = proto_tree_add_subtree(measurement_tree, tvb, offset, intrusion_block_size, ett_sick_cola2_measurement_intrusion, &intrusion_item, "Intrusion Block");

		proto_tree_add_item_ret_uint(intrusion_tree, hf_sick_cola2_measurement_intrusion_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &num_intrusions);
		proto_item_append_text(intrusion_item, " (%u intrusions)", num_intrusions);
		offset += 4;

		for (uint32_t intrusion = 0; intrusion < num_intrusions; intrusion++)
		{
			intrusion_value = tvb_get_letoh24(tvb, offset);
			intrusion_item = proto_tree_add_uint_format(intrusion_tree, hf_sick_cola2_measurement_intrusion, tvb, offset, 3, intrusion_value, "Intrusion #%u: %u", intrusion, intrusion_value);
			intrusion_value_tree = proto_item_add_subtree(intrusion_item, ett_sick_cola2_measurement_intrusion_value);
			proto_tree_add_bitmask_list(intrusion_value_tree, tvb, offset, 3, intrusion_cut_off_path, ENC_LITTLE_ENDIAN);
			offset += 3;
		}
	}

	if (application_io_block_offset > 0)
	{
		static int* const linear_velocity_flags[] = {
			&hf_sick_cola2_measurement_application_lin_vel_flags_vel0_valid,
			&hf_sick_cola2_measurement_application_lin_vel_flags_vel1_valid,
			&hf_sick_cola2_measurement_application_lin_vel_flags_reserved1,
			&hf_sick_cola2_measurement_application_lin_vel_flags_vel0_transmit,
			&hf_sick_cola2_measurement_application_lin_vel_flags_vel1_transmit,
			&hf_sick_cola2_measurement_application_lin_vel_flags_reserved2,
			NULL
		};

		offset = application_io_block_offset;
		application_io_tree = proto_tree_add_subtree(measurement_tree, tvb, offset, application_io_block_size, ett_sick_cola2_measurement_application_io, NULL, "Application I/O Block");

		proto_tree* unsafe_inputs_tree = proto_tree_add_subtree(application_io_tree, tvb, offset, 8, ett_sick_cola2_measurement_application_io_unsafe_inputs, NULL, "Unsafe Inputs");
		proto_tree_add_item(unsafe_inputs_tree, hf_sick_cola2_measurement_application_io_unsafe_inputs_input_source, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(unsafe_inputs_tree, hf_sick_cola2_measurement_application_io_unsafe_inputs_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(application_io_tree, hf_sick_cola2_measurement_application_io_reserved, tvb, offset, 4, ENC_NA);
		offset += 4;

		proto_tree* mon_case_tree = proto_tree_add_subtree(application_io_tree, tvb, offset, (2*20)+4, ett_sick_cola2_measurement_application_io_mon_cases, NULL, "Monitoring Cases");
		for (uint32_t mon = 0; mon < 20; mon++)
		{
			uint16_t mon_value = tvb_get_letohs(tvb, offset);
			proto_tree_add_uint_format(mon_case_tree, hf_sick_cola2_measurement_application_io_mon_case_num, tvb, offset, 2, mon_value, "Monitoring Case No %u: %u", mon, mon_value);
			offset += 2;
		}
		proto_tree_add_item(mon_case_tree, hf_sick_cola2_measurement_application_io_mon_case_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree* lin_vel_tree = proto_tree_add_subtree(application_io_tree, tvb, offset, 6, ett_sick_cola2_measurement_application_io_lin_vel, NULL, "Linear Velocity Inputs");
		proto_tree_add_item(lin_vel_tree, hf_sick_cola2_measurement_application_lin_vel0, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(lin_vel_tree, hf_sick_cola2_measurement_application_lin_vel1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_bitmask(lin_vel_tree, tvb, offset, hf_sick_cola2_measurement_application_lin_vel_flags, ett_sick_cola2_measurement_application_lin_vel_flag, linear_velocity_flags, ENC_LITTLE_ENDIAN);
		offset += 1;
		proto_tree_add_item(lin_vel_tree, hf_sick_cola2_measurement_application_io_reserved, tvb, offset, 1, ENC_NA);
		offset += 1;

		proto_tree_add_item(application_io_tree, hf_sick_cola2_measurement_application_io_reserved, tvb, offset, 12, ENC_NA);
		offset += 12;
		proto_tree_add_item(application_io_tree, hf_sick_cola2_measurement_application_sleep_mode, tvb, offset, 1, ENC_NA);
		offset += 1;
		proto_tree_add_item(application_io_tree, hf_sick_cola2_measurement_application_io_reserved, tvb, offset, 1, ENC_NA);
		offset += 1;

	}

	return tvb_captured_length(tvb);
}


static int
dissect_sick_cola2_measurement_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree      *cola2_tree, *header_tree;
	proto_item      *ti;
	int				offset = 0;
	uint32_t			length, id, fragment_offset;
	conversation_t  *conversation;
	tvbuff_t *next_tvb;
	struct sick_cola2_measurement_data* measurement_data;
	fragment_head   *frag_msg  = NULL;

	if (tvb_get_ntohl(tvb, offset) != SICK_COLA2_MEASUREMENT_MAGIC_NUMBER)
	{
		//not our packet
		return 0;
	}

	conversation = find_or_create_conversation(pinfo);

	//  Is there any data attached to this frame?
	measurement_data = (struct sick_cola2_measurement_data *)p_get_proto_data(wmem_file_scope(), pinfo, proto_sick_cola2_udp, 0);
	if (measurement_data == NULL)
	{
		// Create frame data structure and attach it to the packet.
		measurement_data = wmem_new0(wmem_file_scope(), struct sick_cola2_measurement_data);

		measurement_data->conversation_id = conversation->conv_index;
		measurement_data->more_frags = true;

		p_add_proto_data(wmem_file_scope(), pinfo, proto_sick_cola2_udp, 0, measurement_data);
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CoLa 2.0 Measurement");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_sick_cola2_udp, tvb, offset, -1, ENC_NA);
	cola2_tree = proto_item_add_subtree(ti, ett_sick_cola2_udp);
	header_tree = proto_tree_add_subtree(cola2_tree, tvb, offset, 24, ett_sick_cola2_message, NULL, "Header");

	proto_tree_add_item(header_tree, hf_sick_cola2_udp_magic_number, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(header_tree, hf_sick_cola2_udp_protocol, tvb, offset, 2, ENC_NA|ENC_ASCII);
	offset += 2;

	proto_tree_add_item(header_tree, hf_sick_cola2_udp_major_ver, tvb, offset, 1, ENC_NA);
	offset += 1;
	proto_tree_add_item(header_tree, hf_sick_cola2_udp_minor_ver, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item_ret_uint(header_tree, hf_sick_cola2_udp_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &length);
	offset += 4;

	proto_tree_add_item_ret_uint(header_tree, hf_sick_cola2_udp_id, tvb, offset, 4, ENC_LITTLE_ENDIAN, &id);
	offset += 4;

	proto_tree_add_item_ret_uint(header_tree, hf_sick_cola2_udp_fragment_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &fragment_offset);
	offset += 4;

	proto_tree_add_item(header_tree, hf_sick_cola2_udp_header_reserved, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	uint32_t total_data = fragment_offset + tvb_reported_length_remaining(tvb, offset);
	if (total_data < length)
		col_add_fstr(pinfo->cinfo, COL_INFO, "<Measurement data fragment for ID %u>", id);

	frag_msg = fragment_add(&sick_cola2_measurement_reassembly_table, tvb, offset, pinfo, id, NULL, fragment_offset,
		tvb_reported_length_remaining(tvb, offset), total_data < length);

	next_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled CoLa Measurement Data",
		frag_msg, &sick_cola2_measurement_frag_items, NULL, cola2_tree);
	if (next_tvb)
	{
		dissect_measurement_data(next_tvb, pinfo, cola2_tree, id);
	}

	return tvb_captured_length(tvb);
}

static int
dissect_sick_cola2_measurement(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	dissect_sick_cola2_measurement_pdu(tvb, pinfo, tree, data);
	return tvb_captured_length(tvb);
}

static bool
dissect_sick_cola2_udp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	if (tvb_captured_length(tvb) >= 4) { /* check of data is big enough for base header. */
		uint32_t magic_number = tvb_get_ntohl(tvb, 0);

		if (magic_number == SICK_COLA2_MEASUREMENT_MAGIC_NUMBER)
		{
			dissect_sick_cola2_measurement(tvb, pinfo, tree, data);
			return true;
		}
	}
	return false;
}

void
proto_register_sick_cola2(void)
{
	expert_module_t* expert_sick_cola2;

	static hf_register_info hf[] = {
		{ &hf_sick_cola2_magic_number,
			{ "Magic Number", "sick_cola2.magic_number", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_length,
			{ "Length", "sick_cola2.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_hub_center,
			{ "HubCntr", "sick_cola2.hub_center", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_noc,
			{ "NoC", "sick_cola2.noc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_noc_request,
			{ "Request", "sick_cola2.request", FT_BOOLEAN, 8, NULL, SICK_COLA2_REQUEST_MASK, NULL, HFILL } },
		{ &hf_sick_cola2_noc_sensor_network,
			{ "NOC sensor network", "sick_cola2.noc_sensor_network", FT_UINT8, BASE_HEX, NULL, 0x7F, NULL, HFILL } },
		{ &hf_sick_cola2_socket_index0,
			{ "Socketidx0", "sick_cola2.socket_index0", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_session_id,
			{ "SessionID", "sick_cola2.session_id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_req_id,
			{ "ReqID", "sick_cola2.req_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_cmd,
			{ "Command", "sick_cola2.cmd", FT_CHAR, BASE_HEX, VALS(cola2_command_vals), 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_mode,
			{ "Mode", "sick_cola2.mode", FT_CHAR, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_timeout,
			{ "Timeout", "sick_cola2.timeout", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_client_id,
			{ "ClientID", "sick_cola2.client_id", FT_UINT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_read_int,
			{ "Read Value", "sick_cola2.read_int", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_read_var,
			{ "Read Value", "sick_cola2.read_var", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_read_data,
			{ "Value", "sick_cola2.read_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_method_index,
			{ "Method Index", "sick_cola2.method_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_method_name,
			{ "Method Name", "sick_cola2.method_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_method_int,
			{ "Method Value", "sick_cola2.method_int", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_method_var,
			{ "Method Value", "sick_cola2.method_var", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_answer_value,
			{ "Return Value", "sick_cola2.answer_value", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_error,
			{ "Error", "sick_cola2.error", FT_UINT16, BASE_DEC, VALS(cola2_error_vals), 0x0, NULL, HFILL } },

      /* Request/Response Matching */
		{ &hf_sick_cola2_response_in,
			{ "Response In", "sick_cola2.response_in", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
				"The response to this request is in this frame", HFILL }},
		{ &hf_sick_cola2_response_to,
			{ "Request In", "sick_cola2.response_to", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
				"This is a response to the request in this frame", HFILL }},
		{ &hf_sick_cola2_time,
			{ "Time", "sick_cola2.time", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
				"The time between the request and reponse", HFILL }},

		/* UDP Measurement data */
		{ &hf_sick_cola2_udp_magic_number,
			{ "Magic Number", "sick_cola2_measurement.magic_number", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_udp_protocol,
			{ "Protocol", "sick_cola2_measurement.protocol", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_udp_major_ver,
			{ "Major Version", "sick_cola2_measurement.major_ver", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_udp_minor_ver,
			{ "Minor Version", "sick_cola2_measurement.minor_ver", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_udp_length,
			{ "Length", "sick_cola2_measurement.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_udp_id,
			{ "Identification", "sick_cola2_measurement.id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_udp_fragment_offset,
			{ "Fragment Offset", "sick_cola2_measurement.fragment_offset", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_udp_header_reserved,
			{ "Reserved", "sick_cola2_measurement.header_reserved", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },

		/* UDP Measurement data fragmentation */
		{ &hf_sick_cola2_measurement_fragment,
			{ "Measurement fragment", "sick_cola2_measurement.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x00, "Message fragment", HFILL } },
		{ &hf_sick_cola2_measurement_fragments,
			{ "Measurement Fragments", "sick_cola2_measurement.fragments", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sick_cola2_measurement_fragment_overlap,
			{ "Measurement fragment overlap", "sick_cola2_measurement.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Message fragment overlap", HFILL } },
		{ &hf_sick_cola2_measurement_fragment_overlap_conflicts,
			{ "Measurement fragment overlapping with conflicting data", "sick_cola2_measurement.fragment.overlap.conflicts", FT_BOOLEAN, BASE_NONE, NULL,
			0x0, "Message fragment overlapping with conflicting data", HFILL } },
		{ &hf_sick_cola2_measurement_fragment_multiple_tails,
			{ "Measurement has multiple tail fragments", "sick_cola2_measurement.fragment.multiple_tails",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Message has multiple tail fragments", HFILL } },
		{ &hf_sick_cola2_measurement_fragment_too_long_fragment,
			{ "Measurement fragment too long", "sick_cola2_measurement.fragment.too_long_fragment",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Message fragment too long", HFILL } },
		{ &hf_sick_cola2_measurement_fragment_error,
			{ "Measurement defragmentation error", "sick_cola2_measurement.fragment.error",
			FT_FRAMENUM, BASE_NONE, NULL, 0x00, "Message defragmentation error", HFILL } },
		{ &hf_sick_cola2_measurement_fragment_count,
			{ "Measurement fragment count", "sick_cola2_measurement.fragment.count",
			FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_reassembled_in,
			{ "Reassembled Measurement in frame", "sick_cola2_measurement.reassembled.in",
			FT_FRAMENUM, BASE_NONE, NULL, 0x00, "This DATA fragment is reassembled in this frame", HFILL } },
		{ &hf_sick_cola2_measurement_reassembled_length,
			{ "Reassembled Measurement length", "sick_cola2_measurement.reassembled.length",
			FT_UINT32, BASE_DEC, NULL, 0x00, "The total length of the reassembled payload", HFILL } },


		{ &hf_sick_cola2_measurement_data,
			{ "Measurement Data", "sick_cola2_measurement.data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sick_cola2_measurement_version,
			{ "Version", "sick_cola2_measurement.version", FT_CHAR, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_version_major,
			{ "Major Version", "sick_cola2_measurement.measurement_version_major", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_version_minor,
			{ "Minor Version", "sick_cola2_measurement.measurement_version_minor", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_version_release,
			{ "Release", "sick_cola2_measurement.measurement_version_release", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_device_serial_number,
			{ "Serial Number of Device", "sick_cola2_measurement.device_serial_number", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_system_plug_serial_number,
			{ "Serial Number of System Plug", "sick_cola2_measurement.system_plug_serial_number", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_channel,
			{ "Channel", "sick_cola2_measurement.channel", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_reserved,
			{ "Reserved", "sick_cola2.reserved", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_sequence_num,
			{ "Sequence Number", "sick_cola2_measurement.sequence_num", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_scan_number,
			{ "Scan Number", "sick_cola2_measurement.scan_number", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_timestamp_date,
			{ "Date", "sick_cola2_measurement.timestamp.date", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_timestamp_reserved,
			{ "Reserved", "sick_cola2_measurement.timestamp.reserved", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_timestamp_time,
			{ "Time", "sick_cola2_measurement.timestamp.time", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_sick_cola2_measurement_gen_system_block_offset,
			{ "General System State Block Offset", "sick_cola2_measurement.gen_system.block_offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_block_size,
			{ "General System State Block Size", "sick_cola2_measurement.gen_system.block_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_derived_values_block_offset,
			{ "Derived Values Block Offset", "sick_cola2_measurement.derived_values.block_offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_derived_values_block_size,
			{ "Derived Values Block Size", "sick_cola2_measurement.derived_values.size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_measurement_data_block_offset,
			{ "Measurement Data Block Offset", "sick_cola2_measurement.measurement_data_block.offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_measurement_data_block_size,
			{ "Measurement Data Block Size", "sick_cola2_measurement.measurement_data_block.size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_intrusion_block_offset,
			{ "Intrusion Block Offset", "sick_cola2_measurement.intrusion_block.offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_intrusion_block_size,
			{ "Intrusion Block Size", "sick_cola2_measurement.intrusion_block.size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_application_io_block_offset,
			{ "Application I/O Block Offset", "sick_cola2_measurement.application_io_block.offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_application_io_block_size,
			{ "Application I/O Block Size", "sick_cola2_measurement.application_io_block.size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

		{ &hf_sick_cola2_measurement_gen_system_run_mode_active,
			{ "RunModeActive", "sick_cola2_measurement.gen_system.run_mode_active", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_standby_mode_active,
			{ "StandbyModeActive", "sick_cola2_measurement.gen_system.standby_mode_active", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_contamination_warning,
			{ "Contamination Warning", "sick_cola2_measurement.gen_system.contamination_warning", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_contamination_error,
			{ "Contamination Error", "sick_cola2_measurement.gen_system.contamination_error", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_reference_contour_status,
			{ "ReferenceContourStatus", "sick_cola2_measurement.gen_system.reference_contour_status", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_reference_manipulation_status,
			{ "ReferenceManipulationStatus", "sick_cola2_measurement.gen_system.reference_manipulation_status", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_byte0_reserved,
			{ "Reserved", "sick_cola2_measurement.gen_system.run_mode_active", FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_safe_cut_off_path,
			{ "SafeCutOffPath", "sick_cola2_measurement.gen_system.safe_cut_off_path", FT_UINT24, BASE_HEX, NULL, 0x0FFFFF, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_safe_cut_off_path1,
			{ "SafeCutOffPath01", "sick_cola2_measurement.gen_system.safe_cut_off_path1", FT_BOOLEAN, 24, NULL, 0x000001, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_safe_cut_off_path2,
			{ "SafeCutOffPath02", "sick_cola2_measurement.gen_system.safe_cut_off_path2", FT_BOOLEAN, 24, NULL, 0x000002, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_safe_cut_off_path3,
			{ "SafeCutOffPath03", "sick_cola2_measurement.gen_system.safe_cut_off_path3", FT_BOOLEAN, 24, NULL, 0x000004, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_safe_cut_off_path4,
			{ "SafeCutOffPath04", "sick_cola2_measurement.gen_system.safe_cut_off_path4", FT_BOOLEAN, 24, NULL, 0x000008, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_safe_cut_off_path5,
			{ "SafeCutOffPath05", "sick_cola2_measurement.gen_system.safe_cut_off_path5", FT_BOOLEAN, 24, NULL, 0x000010, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_safe_cut_off_path6,
			{ "SafeCutOffPath06", "sick_cola2_measurement.gen_system.safe_cut_off_path6", FT_BOOLEAN, 24, NULL, 0x000020, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_safe_cut_off_path7,
			{ "SafeCutOffPath07", "sick_cola2_measurement.gen_system.safe_cut_off_path7", FT_BOOLEAN, 24, NULL, 0x000040, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_safe_cut_off_path8,
			{ "SafeCutOffPath08", "sick_cola2_measurement.gen_system.safe_cut_off_path8", FT_BOOLEAN, 24, NULL, 0x000080, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_safe_cut_off_path9,
			{ "SafeCutOffPath09", "sick_cola2_measurement.gen_system.safe_cut_off_path9", FT_BOOLEAN, 24, NULL, 0x000100, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_safe_cut_off_path10,
			{ "SafeCutOffPath10", "sick_cola2_measurement.gen_system.safe_cut_off_path10", FT_BOOLEAN, 24, NULL, 0x000200, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_safe_cut_off_path11,
			{ "SafeCutOffPath11", "sick_cola2_measurement.gen_system.safe_cut_off_path11", FT_BOOLEAN, 24, NULL, 0x000400, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_safe_cut_off_path12,
			{ "SafeCutOffPath12", "sick_cola2_measurement.gen_system.safe_cut_off_path12", FT_BOOLEAN, 24, NULL, 0x000800, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_safe_cut_off_path13,
			{ "SafeCutOffPath13", "sick_cola2_measurement.gen_system.safe_cut_off_path13", FT_BOOLEAN, 24, NULL, 0x001000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_safe_cut_off_path14,
			{ "SafeCutOffPath14", "sick_cola2_measurement.gen_system.safe_cut_off_path14", FT_BOOLEAN, 24, NULL, 0x002000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_safe_cut_off_path15,
			{ "SafeCutOffPath15", "sick_cola2_measurement.gen_system.safe_cut_off_path15", FT_BOOLEAN, 24, NULL, 0x004000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_safe_cut_off_path16,
			{ "SafeCutOffPath16", "sick_cola2_measurement.gen_system.safe_cut_off_path16", FT_BOOLEAN, 24, NULL, 0x008000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_safe_cut_off_path17,
			{ "SafeCutOffPath17", "sick_cola2_measurement.gen_system.safe_cut_off_path17", FT_BOOLEAN, 24, NULL, 0x010000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_safe_cut_off_path18,
			{ "SafeCutOffPath18", "sick_cola2_measurement.gen_system.safe_cut_off_path18", FT_BOOLEAN, 24, NULL, 0x020000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_safe_cut_off_path19,
			{ "SafeCutOffPath19", "sick_cola2_measurement.gen_system.safe_cut_off_path19", FT_BOOLEAN, 24, NULL, 0x040000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_safe_cut_off_path20,
			{ "SafeCutOffPath20", "sick_cola2_measurement.gen_system.safe_cut_off_path20", FT_BOOLEAN, 24, NULL, 0x080000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_safe_cut_off_path_reserved,
			{ "Reserved", "sick_cola2_measurement.gen_system.safe_cut_off_reserved", FT_UINT24, BASE_HEX, NULL, 0xF00000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path,
			{ "NonSafeCutOffPath", "sick_cola2_measurement.gen_system.nonsafe_cut_off_path", FT_UINT24, BASE_HEX, NULL, 0x0FFFFF, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path1,
			{ "NonSafeCutOffPath01", "sick_cola2_measurement.gen_system.nonsafe_cut_off_path1", FT_BOOLEAN, 24, NULL, 0x000001, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path2,
			{ "NonSafeCutOffPath02", "sick_cola2_measurement.gen_system.nonsafe_cut_off_path2", FT_BOOLEAN, 24, NULL, 0x000002, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path3,
			{ "NonSafeCutOffPath03", "sick_cola2_measurement.gen_system.nonsafe_cut_off_path3", FT_BOOLEAN, 24, NULL, 0x000004, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path4,
			{ "NonSafeCutOffPath04", "sick_cola2_measurement.gen_system.nonsafe_cut_off_path4", FT_BOOLEAN, 24, NULL, 0x000008, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path5,
			{ "NonSafeCutOffPath05", "sick_cola2_measurement.gen_system.nonsafe_cut_off_path5", FT_BOOLEAN, 24, NULL, 0x000010, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path6,
			{ "NonSafeCutOffPath06", "sick_cola2_measurement.gen_system.nonsafe_cut_off_path6", FT_BOOLEAN, 24, NULL, 0x000020, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path7,
			{ "NonSafeCutOffPath07", "sick_cola2_measurement.gen_system.nonsafe_cut_off_path7", FT_BOOLEAN, 24, NULL, 0x000040, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path8,
			{ "NonSafeCutOffPath08", "sick_cola2_measurement.gen_system.nonsafe_cut_off_path8", FT_BOOLEAN, 24, NULL, 0x000080, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path9,
			{ "NonSafeCutOffPath09", "sick_cola2_measurement.gen_system.nonsafe_cut_off_path9", FT_BOOLEAN, 24, NULL, 0x000100, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path10,
			{ "NonSafeCutOffPath10", "sick_cola2_measurement.gen_system.nonsafe_cut_off_path10", FT_BOOLEAN, 24, NULL, 0x000200, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path11,
			{ "NonSafeCutOffPath11", "sick_cola2_measurement.gen_system.nonsafe_cut_off_path11", FT_BOOLEAN, 24, NULL, 0x000400, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path12,
			{ "NonSafeCutOffPath12", "sick_cola2_measurement.gen_system.nonsafe_cut_off_path12", FT_BOOLEAN, 24, NULL, 0x000800, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path13,
			{ "NonSafeCutOffPath13", "sick_cola2_measurement.gen_system.nonsafe_cut_off_path13", FT_BOOLEAN, 24, NULL, 0x001000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path14,
			{ "NonSafeCutOffPath14", "sick_cola2_measurement.gen_system.nonsafe_cut_off_path14", FT_BOOLEAN, 24, NULL, 0x002000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path15,
			{ "NonSafeCutOffPath15", "sick_cola2_measurement.gen_system.nonsafe_cut_off_path15", FT_BOOLEAN, 24, NULL, 0x004000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path16,
			{ "NonSafeCutOffPath16", "sick_cola2_measurement.gen_system.nonsafe_cut_off_path16", FT_BOOLEAN, 24, NULL, 0x008000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path17,
			{ "NonSafeCutOffPath17", "sick_cola2_measurement.gen_system.nonsafe_cut_off_path17", FT_BOOLEAN, 24, NULL, 0x010000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path18,
			{ "NonSafeCutOffPath18", "sick_cola2_measurement.gen_system.nonsafe_cut_off_path18", FT_BOOLEAN, 24, NULL, 0x020000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path19,
			{ "NonSafeCutOffPath19", "sick_cola2_measurement.gen_system.nonsafe_cut_off_path19", FT_BOOLEAN, 24, NULL, 0x040000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path20,
			{ "NonSafeCutOffPath20", "sick_cola2_measurement.gen_system.nonsafe_cut_off_path20", FT_BOOLEAN, 24, NULL, 0x080000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_nonsafe_cut_off_path_reserved,
			{ "Reserved", "sick_cola2_measurement.gen_system.nonsafe_cut_off_reserved", FT_UINT24, BASE_HEX, NULL, 0xF00000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path,
			{ "ResetRequiredCutOffPath", "sick_cola2_measurement.gen_system.reset_required_cut_off_path", FT_UINT24, BASE_HEX, NULL, 0x0FFFFF, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path1,
			{ "ResetRequiredCutOffPath01", "sick_cola2_measurement.gen_system.reset_required_cut_off_path1", FT_BOOLEAN, 24, NULL, 0x000001, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path2,
			{ "ResetRequiredCutOffPath02", "sick_cola2_measurement.gen_system.reset_required_cut_off_path2", FT_BOOLEAN, 24, NULL, 0x000002, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path3,
			{ "ResetRequiredCutOffPath03", "sick_cola2_measurement.gen_system.reset_required_cut_off_path3", FT_BOOLEAN, 24, NULL, 0x000004, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path4,
			{ "ResetRequiredCutOffPath04", "sick_cola2_measurement.gen_system.reset_required_cut_off_path4", FT_BOOLEAN, 24, NULL, 0x000008, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path5,
			{ "ResetRequiredCutOffPath05", "sick_cola2_measurement.gen_system.reset_required_cut_off_path5", FT_BOOLEAN, 24, NULL, 0x000010, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path6,
			{ "ResetRequiredCutOffPath06", "sick_cola2_measurement.gen_system.reset_required_cut_off_path6", FT_BOOLEAN, 24, NULL, 0x000020, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path7,
			{ "ResetRequiredCutOffPath07", "sick_cola2_measurement.gen_system.reset_required_cut_off_path7", FT_BOOLEAN, 24, NULL, 0x000040, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path8,
			{ "ResetRequiredCutOffPath08", "sick_cola2_measurement.gen_system.reset_required_cut_off_path8", FT_BOOLEAN, 24, NULL, 0x000080, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path9,
			{ "ResetRequiredCutOffPath09", "sick_cola2_measurement.gen_system.reset_required_cut_off_path9", FT_BOOLEAN, 24, NULL, 0x000100, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path10,
			{ "ResetRequiredCutOffPath10", "sick_cola2_measurement.gen_system.reset_required_cut_off_path10", FT_BOOLEAN, 24, NULL, 0x000200, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path11,
			{ "ResetRequiredCutOffPath11", "sick_cola2_measurement.gen_system.reset_required_cut_off_path11", FT_BOOLEAN, 24, NULL, 0x000400, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path12,
			{ "ResetRequiredCutOffPath12", "sick_cola2_measurement.gen_system.reset_required_cut_off_path12", FT_BOOLEAN, 24, NULL, 0x000800, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path13,
			{ "ResetRequiredCutOffPath13", "sick_cola2_measurement.gen_system.reset_required_cut_off_path13", FT_BOOLEAN, 24, NULL, 0x001000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path14,
			{ "ResetRequiredCutOffPath14", "sick_cola2_measurement.gen_system.reset_required_cut_off_path14", FT_BOOLEAN, 24, NULL, 0x002000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path15,
			{ "ResetRequiredCutOffPath15", "sick_cola2_measurement.gen_system.reset_required_cut_off_path15", FT_BOOLEAN, 24, NULL, 0x004000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path16,
			{ "ResetRequiredCutOffPath16", "sick_cola2_measurement.gen_system.reset_required_cut_off_path16", FT_BOOLEAN, 24, NULL, 0x008000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path17,
			{ "ResetRequiredCutOffPath17", "sick_cola2_measurement.gen_system.reset_required_cut_off_path17", FT_BOOLEAN, 24, NULL, 0x010000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path18,
			{ "ResetRequiredCutOffPath18", "sick_cola2_measurement.gen_system.reset_required_cut_off_path18", FT_BOOLEAN, 24, NULL, 0x020000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path19,
			{ "ResetRequiredCutOffPath19", "sick_cola2_measurement.gen_system.reset_required_cut_off_path19", FT_BOOLEAN, 24, NULL, 0x040000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path20,
			{ "ResetRequiredCutOffPath20", "sick_cola2_measurement.gen_system.reset_required_cut_off_path20", FT_BOOLEAN, 24, NULL, 0x080000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_reset_required_cut_off_path_reserved,
			{ "Reserved", "sick_cola2_measurement.gen_system.reset_required_cut_off_reserved", FT_UINT24, BASE_HEX, NULL, 0xF00000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_cur_mon_case_no_table1,
			{ "Current Monitoring Case (Table 1)", "sick_cola2_measurement.gen_system.cur_mon_case_no_table1", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_cur_mon_case_no_table2,
			{ "Current Monitoring Case (Table 2)", "sick_cola2_measurement.gen_system.cur_mon_case_no_table2", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_cur_mon_case_no_table3,
			{ "Current Monitoring Case (Table 3)", "sick_cola2_measurement.gen_system.cur_mon_case_no_table3", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_cur_mon_case_no_table4,
			{ "Current Monitoring Case (Table 4)", "sick_cola2_measurement.gen_system.cur_mon_case_no_table4", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_reserved14,
			{ "Reserved", "sick_cola2_measurement.gen_system.reserved14", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_application_error,
			{ "ApplicationError", "sick_cola2_measurement.gen_system.application_error", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_device_error,
			{ "DeviceError", "sick_cola2_measurement.gen_system.device_error", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_gen_system_byte15_reserved,
			{ "Reserved", "sick_cola2_measurement.gen_system.byte15_reserved", FT_UINT8, BASE_HEX, NULL, 0xFC, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_derived_values_multiplication_factor,
			{ "Multiplication Factor", "sick_cola2_measurement.derived_values.multiplication_factor", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_derived_values_num_beams,
			{ "Number of Beams", "sick_cola2_measurement.derived_values.num_beams", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_derived_values_scan_time,
			{ "Scan Time", "sick_cola2_measurement.derived_values.scan_time", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_derived_values_reserved,
			{ "Reserved", "sick_cola2_measurement.derived_values.reserved", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_derived_values_start_angle,
			{ "Start Angle", "sick_cola2_measurement.derived_values.start_angle", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sick_cola2_measurement_derived_values_ang_beam_resolution,
			{ "Angular Beam Resolution", "sick_cola2_measurement.derived_values.ang_beam_resolution", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_sick_cola2_measurement_derived_values_interbeam_period,
			{ "Interbeam Period", "sick_cola2_measurement.derived_values.interbeam_period", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_microseconds), 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_measurement_data_num_beams,
			{ "Number of Beams", "sick_cola2_measurement.measurement_data.num_beams", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_measurement_data_beam_distance,
			{ "Distance", "sick_cola2_measurement.measurement_data.beam.distance", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_millimeters), 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_measurement_data_beam_reflectivity,
			{ "Reflectivity", "sick_cola2_measurement.measurement_data.beam.reflectivity", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_measurement_data_beam_status,
			{ "Status", "sick_cola2_measurement.measurement_data.beam.status", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_measurement_data_beam_status_valid,
			{ "Valid", "sick_cola2_measurement.measurement_data.beam.status.valid", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_measurement_data_beam_status_infinite,
			{ "Infinite", "sick_cola2_measurement.measurement_data.beam.status.infinite", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_measurement_data_beam_status_glare,
			{ "Glare", "sick_cola2_measurement.measurement_data.beam.status.glare", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_measurement_data_beam_status_reflector,
			{ "Reflector", "sick_cola2_measurement.measurement_data.beam.status.reflector", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_measurement_data_beam_status_contamination,
			{ "Contamination", "sick_cola2_measurement.measurement_data.beam.status.contamination", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_measurement_data_beam_status_contamination_warning,
			{ "Contamination Warning", "sick_cola2_measurement.measurement_data.beam.status.contamination_warning", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_measurement_data_beam_status_reserved,
			{ "Reserved", "sick_cola2_measurement.measurement_data.beam.status.reserved", FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_intrusion_size,
			{ "Size", "sick_cola2_measurement.intrusion.size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_intrusion,
			{ "Intrusion", "sick_cola2_measurement.intrusion.intrusion", FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_intrusion_cut_off_path1,
			{ "IntrusionCutOffPath01", "sick_cola2_measurement.intrusion.intrusion_cut_off_path1", FT_BOOLEAN, 24, NULL, 0x000001, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_intrusion_cut_off_path2,
			{ "IntrusionCutOffPath02", "sick_cola2_measurement.intrusion.intrusion_cut_off_path2", FT_BOOLEAN, 24, NULL, 0x000002, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_intrusion_cut_off_path3,
			{ "IntrusionCutOffPath03", "sick_cola2_measurement.intrusion.intrusion_cut_off_path3", FT_BOOLEAN, 24, NULL, 0x000004, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_intrusion_cut_off_path4,
			{ "IntrusionCutOffPath04", "sick_cola2_measurement.intrusion.intrusion_cut_off_path4", FT_BOOLEAN, 24, NULL, 0x000008, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_intrusion_cut_off_path5,
			{ "IntrusionCutOffPath05", "sick_cola2_measurement.intrusion.intrusion_cut_off_path5", FT_BOOLEAN, 24, NULL, 0x000010, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_intrusion_cut_off_path6,
			{ "IntrusionCutOffPath06", "sick_cola2_measurement.intrusion.intrusion_cut_off_path6", FT_BOOLEAN, 24, NULL, 0x000020, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_intrusion_cut_off_path7,
			{ "IntrusionCutOffPath07", "sick_cola2_measurement.intrusion.intrusion_cut_off_path7", FT_BOOLEAN, 24, NULL, 0x000040, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_intrusion_cut_off_path8,
			{ "IntrusionCutOffPath08", "sick_cola2_measurement.intrusion.intrusion_cut_off_path8", FT_BOOLEAN, 24, NULL, 0x000080, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_intrusion_cut_off_path9,
			{ "IntrusionCutOffPath09", "sick_cola2_measurement.intrusion.intrusion_cut_off_path9", FT_BOOLEAN, 24, NULL, 0x000100, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_intrusion_cut_off_path10,
			{ "IntrusionCutOffPath10", "sick_cola2_measurement.intrusion.intrusion_cut_off_path10", FT_BOOLEAN, 24, NULL, 0x000200, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_intrusion_cut_off_path11,
			{ "IntrusionCutOffPath11", "sick_cola2_measurement.intrusion.intrusion_cut_off_path11", FT_BOOLEAN, 24, NULL, 0x000400, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_intrusion_cut_off_path12,
			{ "IntrusionCutOffPath12", "sick_cola2_measurement.intrusion.intrusion_cut_off_path12", FT_BOOLEAN, 24, NULL, 0x000800, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_intrusion_cut_off_path13,
			{ "IntrusionCutOffPath13", "sick_cola2_measurement.intrusion.intrusion_cut_off_path13", FT_BOOLEAN, 24, NULL, 0x001000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_intrusion_cut_off_path14,
			{ "IntrusionCutOffPath14", "sick_cola2_measurement.intrusion.intrusion_cut_off_path14", FT_BOOLEAN, 24, NULL, 0x002000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_intrusion_cut_off_path15,
			{ "IntrusionCutOffPath15", "sick_cola2_measurement.intrusion.intrusion_cut_off_path15", FT_BOOLEAN, 24, NULL, 0x004000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_intrusion_cut_off_path16,
			{ "IntrusionCutOffPath16", "sick_cola2_measurement.intrusion.intrusion_cut_off_path16", FT_BOOLEAN, 24, NULL, 0x008000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_intrusion_cut_off_path17,
			{ "IntrusionCutOffPath17", "sick_cola2_measurement.intrusion.intrusion_cut_off_path17", FT_BOOLEAN, 24, NULL, 0x010000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_intrusion_cut_off_path18,
			{ "IntrusionCutOffPath18", "sick_cola2_measurement.intrusion.intrusion_cut_off_path18", FT_BOOLEAN, 24, NULL, 0x020000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_intrusion_cut_off_path19,
			{ "IntrusionCutOffPath19", "sick_cola2_measurement.intrusion.intrusion_cut_off_path19", FT_BOOLEAN, 24, NULL, 0x040000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_intrusion_cut_off_path20,
			{ "IntrusionCutOffPath20", "sick_cola2_measurement.intrusion.intrusion_cut_off_path20", FT_BOOLEAN, 24, NULL, 0x080000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_intrusion_cut_off_path_reserved,
			{ "Reserved", "sick_cola2_measurement.intrusion.intrusion_cut_off_reserved", FT_UINT24, BASE_HEX, NULL, 0xF00000, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_application_io_unsafe_inputs_input_source,
			{ "Input Source", "sick_cola2_measurement.application_io.unsafe_inputs.input_source", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_application_io_unsafe_inputs_flags,
			{ "Flags", "sick_cola2_measurement.application_io.unsafe_inputs.flags", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_application_io_reserved,
			{ "Reserved", "sick_cola2_measurement.application_io.reserved", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_application_io_mon_case_num,
			{ "Size", "sick_cola2_measurement.application_io.mon_case.num", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_application_io_mon_case_flags,
			{ "Flags", "sick_cola2_measurement.application_io.mon_case.flags", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_application_lin_vel0,
			{ "Velocity0", "sick_cola2_measurement.application_io.lin_vel0", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_application_lin_vel1,
			{ "Velocity1", "sick_cola2_measurement.application_io.lin_vel1", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_application_lin_vel_flags,
			{ "Flags", "sick_cola2_measurement.application_io.lin_vel_flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_application_lin_vel_flags_vel0_valid,
			{ "Velocity0 is valid", "sick_cola2_measurement.application_io.lin_vel_flags.vel0_valid", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_application_lin_vel_flags_vel1_valid,
			{ "Velocity1 is valid", "sick_cola2_measurement.application_io.lin_vel_flags.vel1_valid", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_application_lin_vel_flags_reserved1,
			{ "Reserved", "sick_cola2_measurement.application_io.lin_vel_flags.reserved1", FT_UINT8, BASE_HEX, NULL, 0x0C, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_application_lin_vel_flags_vel0_transmit,
			{ "Velocity0 is transmitted safely", "sick_cola2_measurement.application_io.lin_vel_flags.vel0_transmit", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_application_lin_vel_flags_vel1_transmit,
			{ "Velocity1 is transmitted safely", "sick_cola2_measurement.application_io.lin_vel_flags.vel1_transmit", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_application_lin_vel_flags_reserved2,
			{ "Reserved", "sick_cola2_measurement.application_io.lin_vel_flags.reserved2", FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL } },
		{ &hf_sick_cola2_measurement_application_sleep_mode,
			{ "Sleep Mode", "sick_cola2_measurement.application_io.sleep_mode", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },

	};

        static int *ett[] = {
		&ett_sick_cola2,
		&ett_sick_cola2_noc,
		&ett_sick_cola2_message,
		&ett_sick_cola2_command,
		&ett_sick_cola2_udp,
		&ett_sick_cola2_measurement_fragment,
		&ett_sick_cola2_measurement_fragments,
		&ett_sick_cola2_measurement_data,
		&ett_sick_cola2_measurement_data_timestamp,
		&ett_sick_cola2_measurement_gen_system,
		&ett_sick_cola2_measurement_derived_values,
		&ett_sick_cola2_measurement_measurement_data,
		&ett_sick_cola2_measurement_intrusion,
		&ett_sick_cola2_measurement_application_io,
		&ett_sick_cola2_measurement_gen_system_safe_cut_off_path,
		&ett_sick_cola2_measurement_gen_system_nonsafe_cut_off_path,
		&ett_sick_cola2_measurement_gen_system_reset_required_cut_off_path,
		&ett_sick_cola2_measurement_measurement_data_beam,
		&ett_sick_cola2_measurement_measurement_data_beam_status,
		&ett_sick_cola2_measurement_data_blocks,
		&ett_sick_cola2_measurement_intrusion_value,
		&ett_sick_cola2_measurement_application_lin_vel_flag,
		&ett_sick_cola2_measurement_application_io_unsafe_inputs,
		&ett_sick_cola2_measurement_application_io_mon_cases,
		&ett_sick_cola2_measurement_application_io_lin_vel,
	};

	static ei_register_info ei[] = {
		{ &ei_sick_cola_command, { "sick_cola2.command.unknown", PI_PROTOCOL, PI_WARN, "Unknown command", EXPFILL }},
		{ &ei_sick_cola_command_parameter, { "sick_cola2.command.parameter.error", PI_MALFORMED, PI_ERROR, "Command parameter parse error", EXPFILL }},
	};

        cola2_request_hashtable = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), cola2_request_hash, cola2_request_equal);

	proto_sick_cola2 = proto_register_protocol("SICK CoLA 2.0", "CoLA 2.0", "sick_cola2");
	proto_sick_cola2_udp = proto_register_protocol("SICK CoLA 2.0 Measurement Data", "CoLA 2.0 Measurement", "sick_cola2_measurement");

	proto_register_field_array(proto_sick_cola2, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_sick_cola2 = expert_register_protocol(proto_sick_cola2);
	expert_register_field_array(expert_sick_cola2, ei, array_length(ei));
	reassembly_table_register(&sick_cola2_measurement_reassembly_table,
		&addresses_ports_reassembly_table_functions);

}

void
proto_reg_handoff_sick_cola2(void)
{
	dissector_handle_t cola2_handle;

	cola2_handle = create_dissector_handle(dissect_sick_cola2, proto_sick_cola2);
	dissector_add_for_decode_as("tcp.port", cola2_handle);

	heur_dissector_add("tcp", dissect_sick_cola2_heur, "SICK CoLa 2.0 over TCP", "sick_cola2_tcp", proto_sick_cola2, HEURISTIC_ENABLE);
	heur_dissector_add("udp", dissect_sick_cola2_udp_heur, "SICK CoLa 2.0 Measurement over UDP", "sick_cola2_udp", proto_sick_cola2_udp, HEURISTIC_ENABLE);
}

/*
* Editor modelines  -  http://www.wireshark.org/tools/modelines.html
*
* Local variables:
* c-basic-offset: 4
* tab-width: 8
* indent-tabs-mode: t
* End:
*
* vi: set shiftwidth=4 tabstop=8 expandtab:
* :indentSize=4:tabSize=8:noTabs=false:
*/
