/* tcpdiff.c
 * Matches and compares TCP flows in two capture files
 *
 * Copyright 2025 Rustam Kovhaev
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#include <stdio.h>
#include <locale.h>
#include <glib.h>
#include <ws_exit_codes.h>
#include <wsutil/cmdarg_err.h>
#include <wsutil/time_util.h>
#include <wsutil/privileges.h>
#include <wsutil/wslog.h>
#include <wsutil/version_info.h>

#include "globals.h"
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/addr_resolv.h>
#include <epan/follow.h>
#include "ui/taps.h"
#include "ui/cli/tshark-tap.h"
#include "ui/dissect_opts.h"
#include "ui/failure_message.h"
#include "ui/cli/tap-iousers.h"

extern guint get_iousers_count(void);
extern io_users_t *get_iousers_instance(guint index);
extern guint get_follow_streams_count(void);
extern follow_info_t *get_follow_streams_instance(guint index);

typedef enum {
	PROCESS_FILE_SUCCEEDED,
	PROCESS_FILE_ERROR,
	PROCESS_FILE_INTERRUPTED
} process_file_status_t;

typedef enum {
	PASS_SUCCEEDED,
	PASS_READ_ERROR,
	PASS_INTERRUPTED
} pass_status_t;

static bool read_interrupted;

typedef struct cap_file_info {
	const char *file_name;
	wtap *wth;
	uint32_t snaplen;
	GArray *conv_array;
	time_t earliest_packet_time;
	time_t latest_packet_time;
} capinfo_tcpdiff_t;

typedef struct conversation_map {
	conv_id_t file1_conv_id;
	conv_id_t file2_conv_id;
} conversation_map_t;

capinfo_tcpdiff_t file1;
capinfo_tcpdiff_t file2;
capture_file cfile;
GArray *conv_map;

static void process_packet_single_pass(capture_file *cf, epan_dissect_t *edt, int64_t offset, wtap_rec *rec)
{
	frame_data fdata;
	wtap_block_t block = NULL;
	uint32_t cum_bytes = 0;
	frame_data ref_frame;
	frame_data prev_dis_frame;
	static frame_data prev_cap_frame;

	cf->count++;
	frame_data_init(&fdata, cf->count, rec, offset, cum_bytes);

	frame_data_set_before_dissect(&fdata, &cf->elapsed_time, &cf->provider.ref, cf->provider.prev_dis);
	if (cf->provider.ref == &fdata) {
		ref_frame = fdata;
		cf->provider.ref = &ref_frame;
	}

	block = wtap_block_ref(rec->block);
	epan_dissect_run_with_taps(edt, cf->cd_t, rec, &fdata, NULL);

	frame_data_set_after_dissect(&fdata, &cum_bytes);
	prev_dis_frame = fdata;
	cf->provider.prev_dis = &prev_dis_frame;
	prev_cap_frame = fdata;
	cf->provider.prev_cap = &prev_cap_frame;

	epan_dissect_reset(edt);
	frame_data_destroy(&fdata);
	rec->block = block;
}

static pass_status_t process_cap_file_single_pass(capture_file *cf, int *err, char **err_info)
{
	wtap_rec rec;
	int framenum = 0;
	epan_dissect_t *edt = NULL;
	int64_t data_offset;
	pass_status_t status = PASS_SUCCEEDED;

	wtap_rec_init(&rec, 1514);
	edt = epan_dissect_new(cf->epan, true, false);

	*err = 0;
	while (wtap_read(cf->provider.wth, &rec, err, err_info, &data_offset)) {
		if (read_interrupted) {
			status = PASS_INTERRUPTED;
			break;
		}
		framenum++;
		ws_debug("tcpdiff: processing packet #%d", framenum);
		process_packet_single_pass(cf, edt, data_offset, &rec);
		wtap_rec_reset(&rec);
	}
	if (*err != 0)
		status = PASS_READ_ERROR;

	epan_dissect_free(edt);
	wtap_rec_cleanup(&rec);
	return status;
}

static process_file_status_t process_cap_file(capture_file *cf)
{
	process_file_status_t status = PROCESS_FILE_SUCCEEDED;
	pass_status_t pass_status;
	int err = 0;
	char *err_info = NULL;

	pass_status = process_cap_file_single_pass(cf, &err, &err_info);
	ws_debug("tcpdiff: done with single pass");

	if (pass_status == PASS_INTERRUPTED)
		status = PROCESS_FILE_INTERRUPTED;

	if (pass_status == PASS_READ_ERROR) {
		ws_debug("tcpdiff: something failed along the line (%d)", err);
		cfile_read_failure_message(cf->filename, err, err_info);
		status = PROCESS_FILE_ERROR;
	}

	wtap_close(cf->provider.wth);
	cf->provider.wth = NULL;
	return status;
}

static void cap_close(capture_file *cf)
{
	if (cf->state == FILE_CLOSED)
		return;

	if (cf->provider.wth != NULL) {
		wtap_close(cf->provider.wth);
		cf->provider.wth = NULL;
	}

	if (cf->filename != NULL) {
		g_free(cf->filename);
		cf->filename = NULL;
	}

	cf->state = FILE_CLOSED;
}

static epan_t *tcpdiff_epan_new(capture_file *cf)
{
	static const struct packet_provider_funcs funcs = {
		cap_file_provider_get_frame_ts,
		cap_file_provider_get_start_ts,
		cap_file_provider_get_interface_name,
		cap_file_provider_get_interface_description,
		NULL, NULL, NULL, NULL
	};

	return epan_new(&cf->provider, &funcs);
}

static cf_status_t cap_open(capture_file *cf, const char *fname, int *err)
{
	wtap *wth;
	char *err_info;

	wth = wtap_open_offline(fname, WTAP_TYPE_AUTO, err, &err_info, false);
	if (!wth) {
		cfile_open_failure_message(fname, *err, err_info);
		return CF_ERROR;
	}

	cf->provider.wth = wth;
	cf->filename = g_strdup(fname);
	cf->cd_t = wtap_file_type_subtype(cf->provider.wth);
	cf->open_type = WTAP_TYPE_AUTO;
	cf->snap = wtap_snapshot_length(cf->provider.wth);
	cf->state = FILE_READ_IN_PROGRESS;
	epan_free(cf->epan);
	cf->epan = tcpdiff_epan_new(cf);
	return CF_OK;
}

static bool file_time_ranges_overlap(void)
{
	return (file1.earliest_packet_time <= file2.latest_packet_time &&
			file2.earliest_packet_time <= file1.latest_packet_time);
}

static bool conversation_equal(conv_item_t *item1, conv_item_t *item2)
{
	if (!item1->start_abs_time.secs || !item2->start_abs_time.secs)
		return false;

	if (llabs(item1->start_abs_time.secs - item2->start_abs_time.secs) > 5)
		return false;

	if (item1->src_port == item2->src_port && item1->dst_port == item2->dst_port &&
			addresses_equal(&item1->src_address, &item2->src_address) &&
			addresses_equal(&item1->dst_address, &item2->dst_address)) {
		return true;
	}

	return false;
}

static void map_conversations(void)
{
	unsigned int i, j;
	GArray *conv1 = file1.conv_array;
	GArray *conv2 = file2.conv_array;
	conv_item_t *iui1;
	conv_item_t *iui2;
	conversation_map_t *item;

	conv_map = g_array_new(false, false, sizeof(conversation_map_t));

	for (i = 0; (conv1 && i < conv1->len); i++) {
		iui1 = &g_array_index(conv1, conv_item_t, i);
		for (j = 0; (conv2 && j < conv2->len); j++) {
			iui2 = &g_array_index(conv2, conv_item_t, j);
			if (!conversation_equal(iui1, iui2))
				continue;
			item = g_new(conversation_map_t, 1);
			item->file1_conv_id = iui1->conv_id;
			item->file2_conv_id = iui2->conv_id;
			g_array_append_val(conv_map, *item);
			break;
		}
	}
}

static void print_conversations(void)
{
	conv_item_t *iui;
	struct tm *tm_time;
	unsigned int i;

	if (conv_map->len == 0)
		return;

	printf("==========================================================================================================================================\n");
	printf("Matching TCP streams in source and target files\n");
	printf("                                                          <-               ->            Total            Absolute Date           Duration\n");

	for (i = 0; (conv_map && i < conv_map->len); i++) {
		char *src_addr, *dst_addr;
		char *rx_bytes, *tx_bytes, *total_bytes;
		char *src, *dst, *src_port, *dst_port;
		char id[20];
		conversation_map_t *item;

		item = &g_array_index(conv_map, conversation_map_t, i);
		iui = &g_array_index(file1.conv_array, conv_item_t, item->file1_conv_id);

		src_addr = get_conversation_address(NULL, &iui->src_address, false);
		dst_addr = get_conversation_address(NULL, &iui->dst_address, false);

		src_port = get_conversation_port(NULL, iui->src_port, iui->ctype, true);
		dst_port = get_conversation_port(NULL, iui->dst_port, iui->ctype, true);
		src = wmem_strconcat(NULL, src_addr, ":", src_port, NULL);
		dst = wmem_strconcat(NULL, dst_addr, ":", dst_port, NULL);
		snprintf(id, sizeof(id), "%d.", i);
		printf("%-5s %-20s  <->  %-20s", id, src, dst);
		wmem_free(NULL, src_port);
		wmem_free(NULL, dst_port);
		wmem_free(NULL, src);
		wmem_free(NULL, dst);

		rx_bytes = format_size(iui->rx_bytes, FORMAT_SIZE_UNIT_BYTES, 0);
		tx_bytes = format_size(iui->tx_bytes, FORMAT_SIZE_UNIT_BYTES, 0);
		total_bytes = format_size(iui->tx_bytes + iui->rx_bytes, FORMAT_SIZE_UNIT_BYTES, 0);
		printf("  %-16s %-16s %-16s ", rx_bytes, tx_bytes, total_bytes);
		wmem_free(NULL, rx_bytes);
		wmem_free(NULL, tx_bytes);
		wmem_free(NULL, total_bytes);

		wmem_free(NULL, src_addr);
		wmem_free(NULL, dst_addr);

		tm_time = localtime(&iui->start_abs_time.secs);
		if (tm_time != NULL) {
			printf("%04d-%02d-%02d %02d:%02d:%02d",
				 tm_time->tm_year + 1900, tm_time->tm_mon + 1, tm_time->tm_mday,
				 tm_time->tm_hour, tm_time->tm_min, tm_time->tm_sec);
		} else
			printf("XXXX-XX-XX XX:XX:XX");
		printf(" %12.4f\n", nstime_to_sec(&iui->stop_time) - nstime_to_sec(&iui->start_time));
	}
	printf("==========================================================================================================================================\n");
}

static void print_file_info(void *arg, capinfo_tcpdiff_t *cf_info)
{
	io_users_t *iu = (io_users_t *)arg;
	conv_item_t *iui;
	struct tm *tm_time;
	unsigned int i;
	int err;
	char *err_info;
	time_t earliest_packet_time = 0;
	time_t latest_packet_time = 0;
	const char *filename = cf_info->file_name;
	wtap_block_t shb;
	unsigned int num_interfaces;
	wtapng_iface_descriptions_t *idb_info;
	char *str;

	cf_info->wth = wtap_open_offline(filename, WTAP_TYPE_AUTO, &err, &err_info, false);
	if (!cf_info->wth) {
		cfile_open_failure_message(filename, err, err_info);
		return;
	}

	cf_info->snaplen = wtap_snapshot_length(cf_info->wth);
	printf("File name:           %s\n", filename);
	printf("Snapshot length:     %d\n", cf_info->snaplen);

	for (unsigned int section_number = 0; section_number < wtap_file_get_num_shbs(cf_info->wth); section_number++) {
		shb = wtap_file_get_shb(cf_info->wth, section_number);
		if (shb == NULL)
			continue;
		if (wtap_block_get_string_option_value(shb, OPT_SHB_HARDWARE, &str) == WTAP_OPTTYPE_SUCCESS)
			printf("Capture hardware:    %s\n", str);
		if (wtap_block_get_string_option_value(shb, OPT_SHB_OS, &str) == WTAP_OPTTYPE_SUCCESS)
			printf("Capture oper-sys:    %s\n", str);
		if (wtap_block_get_string_option_value(shb, OPT_SHB_USERAPPL, &str) == WTAP_OPTTYPE_SUCCESS)
			printf("Capture application: %s\n", str);
	}

	str = NULL;
	idb_info = wtap_file_get_idb_info(cf_info->wth);
	num_interfaces = idb_info->interface_data->len;
	printf("Number of interfaces in file: %u\n", num_interfaces);
	for (i = 0; i < num_interfaces; i++) {
		const wtap_block_t if_descr = g_array_index(idb_info->interface_data, wtap_block_t, i);
		str = wtap_get_debug_if_descr(if_descr, 21, "\n");
		printf("Interface #%u info:\n", i);
		printf("%s", str);
	}
	g_free(idb_info);
	wtap_close(cf_info->wth);

	for (i = 0; (iu->hash.conv_array && i < iu->hash.conv_array->len); i++) {
		iui = &g_array_index(iu->hash.conv_array, conv_item_t, i);
		if (earliest_packet_time == 0)
			earliest_packet_time = iui->start_abs_time.secs;
		else if (iui->start_abs_time.secs < earliest_packet_time)
			earliest_packet_time = iui->start_abs_time.secs;

		if (latest_packet_time == 0)
			latest_packet_time = earliest_packet_time +  iui->stop_time.secs;
		else if (latest_packet_time < earliest_packet_time + iui->stop_time.secs)
			latest_packet_time = earliest_packet_time + iui->stop_time.secs;
	}

	cf_info->earliest_packet_time = earliest_packet_time;
	cf_info->latest_packet_time = latest_packet_time;
	if (latest_packet_time != 0 &&  earliest_packet_time != 0)
		printf("Capture duration:    %ld seconds\n", latest_packet_time - earliest_packet_time);

	tm_time = localtime(&earliest_packet_time);
	if (tm_time != NULL)
		printf("Earliest packet:     %04d-%02d-%02d %02d:%02d:%02d\n", tm_time->tm_year + 1900,
				tm_time->tm_mon + 1, tm_time->tm_mday, tm_time->tm_hour, tm_time->tm_min, tm_time->tm_sec);

	tm_time = localtime(&latest_packet_time);
	if (tm_time != NULL)
		printf("Latest packet:       %04d-%02d-%02d %02d:%02d:%02d\n", tm_time->tm_year + 1900,
				tm_time->tm_mon + 1, tm_time->tm_mday, tm_time->tm_hour, tm_time->tm_min, tm_time->tm_sec);

	printf("\n");
}

static void diff_payloads(follow_info_t *follow_info1, follow_info_t *follow_info2)
{
	char buf[WS_INET6_ADDRSTRLEN];
	GList *cur;
	GList *cur2;
	follow_record_t *record1;
	follow_record_t *record2;
	GByteArray *stream1_client = g_byte_array_new();
	GByteArray *stream1_server = g_byte_array_new();
	GByteArray *stream2_client = g_byte_array_new();
	GByteArray *stream2_server = g_byte_array_new();

	/* Print header */
	address_to_str_buf(&follow_info1->client_ip, buf, sizeof(buf));
	if (follow_info1->client_ip.type == AT_IPv6)
		printf("Node 0: [%s]:%u\n", buf, follow_info1->client_port);
	else
		printf("Node 0: %s:%u\n", buf, follow_info1->client_port);

	address_to_str_buf(&follow_info1->server_ip, buf, sizeof(buf));
	if (follow_info1->server_ip.type == AT_IPv6)
		printf("Node 1: [%s]:%u\n", buf, follow_info1->server_port);
	else
		printf("Node 1: %s:%u\n", buf, follow_info1->server_port);

	for (cur = g_list_last(follow_info1->payload); cur != NULL; cur = g_list_previous(cur)) {
		record1 = (follow_record_t *)cur->data;
		if (!record1->is_server)
			g_byte_array_append(stream1_client, record1->data->data, record1->data->len);
		else
			g_byte_array_append(stream1_server, record1->data->data, record1->data->len);
	}

	for (cur2 = g_list_last(follow_info2->payload); cur2 != NULL; cur2 = g_list_previous(cur2)) {
		record2 = (follow_record_t *)cur2->data;
		if (!record2->is_server)
			g_byte_array_append(stream2_client, record2->data->data, record2->data->len);
		else
			g_byte_array_append(stream2_server, record2->data->data, record2->data->len);
	}

	// File #1 sent / File #2 received
	for (guint i = 0; i < MIN(stream1_client->len, stream2_client->len); i++) {
		if (stream1_client->data[i] != stream2_client->data[i])
			printf("%u: %X %X\n", i, stream1_client->data[i], stream2_client->data[i]);
	}

	// File #1 received / File #2 sent
	for (guint i = 0; i < MIN(stream1_server->len, stream2_server->len); i++) {
		if (stream1_server->data[i] != stream2_server->data[i])
			printf("\t %u: %X %X\n", i, stream1_server->data[i], stream2_server->data[i]);
	}
}

static void analyze_termination(follow_info_t *follow_info1, follow_info_t *follow_info2)
{
	if (follow_info1->tcp_rst_with_data || follow_info2->tcp_rst_with_data)
		printf("TCP RST with payload, most likely active/smart network hardware/software between client and server is to blame\n");

	if (follow_info1->tcp_rst[FROM_CLIENT] != follow_info2->tcp_rst[FROM_CLIENT] ||
			follow_info1->tcp_rst[FROM_SERVER] != follow_info2->tcp_rst[FROM_SERVER])
		printf("Both client and server did not send each other TCP RST, most likely active/smart network hardware/software between client and server sent TCP RST to both parties\n");

	if (follow_info1->bytes_written[FROM_CLIENT] != follow_info2->bytes_written[FROM_CLIENT]) {
		printf("File #1 sent bytes: %d\n", follow_info1->bytes_written[FROM_CLIENT]);
		printf("File #2 received bytes: %d\n", follow_info2->bytes_written[FROM_CLIENT]);
	}

	if (follow_info1->bytes_written[FROM_SERVER] != follow_info2->bytes_written[FROM_SERVER]) {
		printf("File #1 received bytes: %d\n", follow_info1->bytes_written[FROM_SERVER]);
		printf("File #2 sent bytes: %d\n", follow_info2->bytes_written[FROM_SERVER]);
	}
}

static void compare_streams(void)
{
	int err, id;
	char res1[64] = {0};
	char res2[64] = {0};
	follow_info_t *stream1;
	follow_info_t *stream2;
	conversation_map_t *item;

	printf("Enter stream number: ");
	if (scanf("%d", &id) != 1)
		return;

	if ((guint) id + 1 > conv_map->len) {
		printf("tcpdiff: Wrong stream number\n");
		return;
	}

	item = &g_array_index(conv_map, conversation_map_t, id);
	snprintf(res1, sizeof(res1), "%s%d", "follow,tcp,hex,", item->file1_conv_id);
	snprintf(res2, sizeof(res2), "%s%d", "follow,tcp,hex,", item->file2_conv_id);

	remove_all_tap_listeners();
	conversation_init();
	process_stat_cmd_arg(res1);
	cap_file_init(&cfile);
	if (cap_open(&cfile, file1.file_name, &err) != CF_OK) {
		cfile_open_failure_message(file1.file_name, err, NULL);
		return;
	}
	start_requested_stats();
	if (process_cap_file(&cfile) != PROCESS_FILE_SUCCEEDED)
		return;
	cap_close(&cfile);

	remove_all_tap_listeners();
	conversation_init();
	process_stat_cmd_arg(res2);
	cap_file_init(&cfile);
	if (cap_open(&cfile, file2.file_name, &err) != CF_OK) {
		cfile_open_failure_message(file2.file_name, err, NULL);
		return;
	}
	start_requested_stats();
	if (process_cap_file(&cfile) != PROCESS_FILE_SUCCEEDED)
		return;
	cap_close(&cfile);

	stream1 = get_follow_streams_instance(0);
	stream2 = get_follow_streams_instance(1);
	diff_payloads(stream1, stream2);
	analyze_termination(stream1, stream2);
}

static void print_usage_tcpdiff(void)
{
	fprintf(stderr, "\nUsage: tcpdiff <file1> <file2>\n");
}

static void read_cleanup(int signum _U_)
{
	/* tell the read to stop */
	read_interrupted = true;
}

int main(int argc, char *argv[])
{
	process_file_status_t status;
	int exit_status = EXIT_SUCCESS;
	int err;
	struct sigaction action, oldaction;
	io_users_t *inst = NULL;

	if (argc < 3) {
		print_usage_tcpdiff();
		exit(2);
	}

	file1.file_name = argv[1];
	file2.file_name = argv[2];

	g_set_prgname("tcpdiff");
	setlocale(LC_ALL, "");
	ws_tzset();

	memset(&action, 0, sizeof(action));
	action.sa_handler = read_cleanup;
	action.sa_flags = SA_RESTART;
	sigemptyset(&action.sa_mask);
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGHUP, NULL, &oldaction);
	if (oldaction.sa_handler == SIG_DFL)
		sigaction(SIGHUP, &action, NULL);

	cmdarg_err_init(stderr_cmdarg_err, stderr_cmdarg_err_cont);
	ws_log_init(vcmdarg_err);
	ws_debug("tcpdiff started with %d args", argc);

	init_process_policies();
	relinquish_special_privs_perm();

	ws_init_version_info("tcpdiff", NULL, NULL);
	init_report_failure_message("tcpdiff");

	timestamp_set_type(TS_RELATIVE);
	timestamp_set_precision(TS_PREC_AUTO);
	timestamp_set_seconds_type(TS_SECONDS_DEFAULT);

	wtap_init(true);

	if (!epan_init(NULL, NULL, true))
		return WS_EXIT_INIT_FAILED;

	register_all_tap_listeners(tap_reg_listener);
	conversation_table_set_gui_info(init_iousers);

	disable_name_resolution();
	global_dissect_options.time_format = TS_ABSOLUTE_WITH_YMD;
	timestamp_set_type(global_dissect_options.time_format);
	process_stat_cmd_arg("conv,tcp");

	proto_disable_all();
	global_dissect_options.enable_protocol_slist = g_slist_append(global_dissect_options.enable_protocol_slist, "eth");
	global_dissect_options.enable_protocol_slist = g_slist_append(global_dissect_options.enable_protocol_slist, "ip");
	global_dissect_options.enable_protocol_slist = g_slist_append(global_dissect_options.enable_protocol_slist, "tcp");
	if (!setup_enabled_and_disabled_protocols()) {
		exit_status = WS_EXIT_INVALID_OPTION;
		goto cleanup;
	}

	cap_file_init(&cfile);
	if (cap_open(&cfile, file1.file_name, &err) != CF_OK) {
		cfile_open_failure_message(file1.file_name, err, NULL);
		exit_status = WS_EXIT_INVALID_FILE;
		goto cleanup;
	}
	start_requested_stats();
	status = process_cap_file(&cfile);
	if (status) {
		exit_status = WS_EXIT_INVALID_FILE;
		goto cleanup;
	}
	inst = get_iousers_instance(0);
	file1.conv_array = g_array_copy(inst->hash.conv_array);
	print_file_info(inst, &file1);
	cap_close(&cfile);
	inst->hash.conv_array = NULL;
	inst->hash.hashtable = NULL;

	conversation_init();
	cap_file_init(&cfile);
	if (cap_open(&cfile, file2.file_name, &err) != CF_OK) {
		cfile_open_failure_message(file2.file_name, err, NULL);
		exit_status = WS_EXIT_INVALID_FILE;
		goto cleanup;
	}
	start_requested_stats();
	status = process_cap_file(&cfile);
	if (status) {
		exit_status = WS_EXIT_INVALID_FILE;
		goto cleanup;
	}
	file2.conv_array = g_array_copy(inst->hash.conv_array);
	print_file_info(inst, &file2);
	cap_close(&cfile);
	inst->hash.conv_array = NULL;
	inst->hash.hashtable = NULL;

	if (!file_time_ranges_overlap()) {
		fprintf(stderr, "tcpdiff: time ranges in the capture files do not overlap, there are no tcp streams to diff\n");
		goto cleanup;
	}

	map_conversations();
	print_conversations();
	compare_streams();

cleanup:
	epan_free(cfile.epan);
	epan_cleanup();
	cap_close(&cfile);
	wtap_cleanup();
	return exit_status;
}
