/* packet-wccp.c
 * Routines for Web Cache Coordination Protocol dissection
 * Jerry Talkington <jerryt@netapp.com>
 *
 * $Id: packet-wccp.c,v 1.28 2002/01/30 23:08:26 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include "packet-wccp.h"

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

static int proto_wccp = -1;
static int hf_wccp_message_type = -1;	/* the message type */
static int hf_wccp_version = -1;	/* protocol version */
static int hf_hash_revision = -1;	/* the version of the hash */
static int hf_change_num = -1;		/* change number */
static int hf_recvd_id = -1;			
static int hf_cache_ip = -1;

static gint ett_wccp = -1;
static gint ett_cache_count = -1;
static gint ett_buckets = -1;
static gint ett_flags = -1;
static gint ett_cache_info = -1;
static gint ett_security_info = -1;
static gint ett_service_info = -1;
static gint ett_service_flags = -1;
static gint ett_router_identity_element = -1;
static gint ett_router_identity_info = -1;
static gint ett_wc_identity_element = -1;
static gint ett_wc_identity_info = -1;
static gint ett_router_view_info = -1;
static gint ett_wc_view_info = -1;
static gint ett_router_assignment_element = -1;
static gint ett_router_assignment_info = -1;
static gint ett_query_info = -1;
static gint ett_capabilities_info = -1;
static gint ett_capability_element = -1;
static gint ett_capability_forwarding_method = -1;
static gint ett_capability_assignment_method = -1;
static gint ett_capability_return_method = -1;
static gint ett_unknown_info = -1;

/*
 * At
 *
 *	http://www.alternic.org/drafts/drafts-f-g/draft-forster-wrec-wccp-v1-00.html
 *
 * is a copy of the now-expired Internet-Draft for WCCP 1.0.
 *
 * At
 *
 *	http://search.ietf.org/internet-drafts/draft-wilson-wrec-wccp-v2-01.txt
 *
 * is an Internet-Draft for WCCP 2.0.
 */

#define UDP_PORT_WCCP	2048

#define WCCPv1			4
#define WCCPv2			0x0200
#define WCCP_HERE_I_AM		7
#define WCCP_I_SEE_YOU		8
#define WCCP_ASSIGN_BUCKET	9
#define WCCP2_HERE_I_AM		10
#define WCCP2_I_SEE_YOU		11
#define WCCP2_REDIRECT_ASSIGN	12
#define WCCP2_REMOVAL_QUERY	13

static const value_string wccp_type_vals[] = {
    { WCCP_HERE_I_AM,        "1.0 Here I am" },
    { WCCP_I_SEE_YOU,        "1.0 I see you" },
    { WCCP_ASSIGN_BUCKET,    "1.0 Assign bucket" },
    { WCCP2_HERE_I_AM,       "2.0 Here I am" },
    { WCCP2_I_SEE_YOU,       "2.0 I see you" },
    { WCCP2_REDIRECT_ASSIGN, "2.0 Redirect assign" },
    { WCCP2_REMOVAL_QUERY,   "2.0 Removal query" },
    { 0,                     NULL }
};

static const value_string wccp_version_val[] = {
	{ WCCPv1, "1"},
	{ WCCPv2, "2"},
	{ 0, NULL}
};

#define HASH_INFO_SIZE	(4*(1+8+1))

#define	WCCP_U_FLAG	0x80000000

#define WCCP2_SECURITY_INFO		0
#define WCCP2_SERVICE_INFO		1
#define WCCP2_ROUTER_ID_INFO		2
#define WCCP2_WC_ID_INFO		3
#define WCCP2_RTR_VIEW_INFO		4
#define WCCP2_WC_VIEW_INFO		5
#define WCCP2_REDIRECT_ASSIGNMENT	6
#define WCCP2_QUERY_INFO		7
#define WCCP2_CAPABILITIES_INFO		8
#define WCCP2_ALT_ASSIGNMENT		13
#define WCCP2_ASSIGN_MAP		14
#define WCCP2_COMMAND_EXTENSION		15

static const value_string info_type_vals[] = {
	{ WCCP2_SECURITY_INFO,       "Security Info" },
	{ WCCP2_SERVICE_INFO,        "Service Info" },
	{ WCCP2_ROUTER_ID_INFO,      "Router Identity Info" },
	{ WCCP2_WC_ID_INFO,          "Web-Cache Identity Info" },
	{ WCCP2_RTR_VIEW_INFO,       "Router View Info" },
	{ WCCP2_WC_VIEW_INFO,        "Web-Cache View Info" },
	{ WCCP2_REDIRECT_ASSIGNMENT, "Assignment Info" },
	{ WCCP2_QUERY_INFO,          "Query Info" },
	{ WCCP2_CAPABILITIES_INFO,   "Capabilities Info" },
	{ WCCP2_COMMAND_EXTENSION,   "Command Extension" },
	{ 0,                         NULL }
};

const value_string service_id_vals[] = {
    { 0x00, "HTTP" },
    { 0,    NULL }
};

typedef struct capability_flag {
	guint32 value;
	const char *short_name;
	const char *long_name;
} capability_flag;

static void dissect_hash_data(tvbuff_t *tvb, int offset,
    proto_tree *wccp_tree);
static void dissect_web_cache_list_entry(tvbuff_t *tvb, int offset,
    int index, proto_tree *wccp_tree);
static int wccp_bucket_info(guint8 bucket_info, proto_tree *bucket_tree,
    guint32 start, tvbuff_t *tvb, int offset);
static gchar *bucket_name(guint8 bucket);
static guint16 dissect_wccp2_header(tvbuff_t *tvb, int offset,
    proto_tree *wccp_tree);
static void dissect_wccp2_info(tvbuff_t *tvb, int offset, guint16 length,
    proto_tree *wccp_tree);
static gboolean dissect_wccp2_security_info(tvbuff_t *tvb, int offset,
    int length, proto_tree *info_tree);
static gboolean dissect_wccp2_service_info(tvbuff_t *tvb, int offset,
    int length, proto_tree *info_tree);
static gboolean dissect_wccp2_router_identity_info(tvbuff_t *tvb,
    int offset, int length, proto_tree *info_tree);
static gboolean dissect_wccp2_wc_identity_info(tvbuff_t *tvb, int offset,
    int length, proto_tree *info_tree);
static gboolean dissect_wccp2_router_view_info(tvbuff_t *tvb, int offset,
    int length, proto_tree *info_tree);
static gboolean dissect_wccp2_wc_view_info(tvbuff_t *tvb, int offset,
    int length, proto_tree *info_tree);
static gboolean dissect_wccp2_assignment_info(tvbuff_t *tvb, int offset,
    int length, proto_tree *info_tree);
static gboolean dissect_wccp2_router_query_info(tvbuff_t *tvb, int offset,
    int length, proto_tree *info_tree);
static gboolean dissect_wccp2_capability_info(tvbuff_t *tvb, int offset,
    int length, proto_tree *info_tree);
static void dissect_32_bit_capability_flags(tvbuff_t *tvb, int curr_offset,
    guint16 capability_len, gint ett, const capability_flag *flags,
    proto_tree *element_tree);

static void 
dissect_wccp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	proto_tree *wccp_tree = NULL;
	proto_item *wccp_tree_item;
	guint32 wccp_message_type;
	guint16 length;
	guint32 cache_count;
	guint i;

	if(check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "WCCP");
	}
	if(check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
	}

	wccp_message_type = tvb_get_ntohl(tvb, offset);

	if(check_col(pinfo->cinfo, COL_INFO)) {
		col_add_str(pinfo->cinfo, COL_INFO, val_to_str(wccp_message_type,
		    wccp_type_vals, "Unknown WCCP message (%u)"));
	}

	if(tree != NULL) {
		wccp_tree_item = proto_tree_add_item(tree, proto_wccp, tvb, offset,
		    -1, FALSE);
		wccp_tree = proto_item_add_subtree(wccp_tree_item, ett_wccp);

		proto_tree_add_uint(wccp_tree, hf_wccp_message_type, tvb, offset,
		    sizeof(wccp_message_type), wccp_message_type);
		offset += sizeof(wccp_message_type);

		switch (wccp_message_type) {

		case WCCP_HERE_I_AM:
			proto_tree_add_item(wccp_tree, hf_wccp_version, tvb,
			    offset, 4, FALSE);
			offset += 4;
			dissect_hash_data(tvb, offset, wccp_tree);
			offset += HASH_INFO_SIZE;
			proto_tree_add_item(wccp_tree, hf_recvd_id, tvb, offset,
			    4, FALSE);
			offset += 4;
			break;

		case WCCP_I_SEE_YOU:
			proto_tree_add_item(wccp_tree, hf_wccp_version, tvb,
			    offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(wccp_tree, hf_change_num, tvb, offset,
			    4, FALSE);
			offset += 4;
			proto_tree_add_item(wccp_tree, hf_recvd_id, tvb, offset,
			    4, FALSE);
			offset += 4;
			cache_count = tvb_get_ntohl(tvb, offset);
			proto_tree_add_text(wccp_tree, tvb, offset, 4,
			    "Number of Web Caches: %u", cache_count);
			offset += 4;
			for (i = 0; i < cache_count; i++) {
				dissect_web_cache_list_entry(tvb, offset, i,
				    wccp_tree);
				offset += 4 + HASH_INFO_SIZE;
			}
			break;

		case WCCP_ASSIGN_BUCKET:
			/*
			 * This hasn't been tested, since I don't have any
			 * traces with this in it.
			 *
			 * The V1 spec claims that this does, indeed,
			 * have a Received ID field after the type,
			 * rather than a Version field.
			 */
			proto_tree_add_item(wccp_tree, hf_recvd_id, tvb, offset,
			    4, FALSE);
			offset += 4;
			cache_count = tvb_get_ntohl(tvb, offset);
			proto_tree_add_text(wccp_tree, tvb, offset, 4,
			    "Number of Web Caches: %u", cache_count);
			offset += 4;
			for (i = 0; i < cache_count; i++) {
				proto_tree_add_ipv4_format(wccp_tree,
				    hf_cache_ip, tvb, offset, 4,
				    tvb_get_ntohl(tvb, offset),
				    "Web Cache %d IP Address: %s", i,
				    ip_to_str(tvb_get_ptr(tvb, offset, 4)));
				offset += 4;
			}
			for (i = 0; i < 256; i += 4) {
				proto_tree_add_text(wccp_tree, tvb, offset, 4,
				    "Buckets %d - %d: %10s %10s %10s %10s",
				    i, i + 3,
				    bucket_name(tvb_get_guint8(tvb, offset)),
				    bucket_name(tvb_get_guint8(tvb, offset+1)),
				    bucket_name(tvb_get_guint8(tvb, offset+2)),
				    bucket_name(tvb_get_guint8(tvb, offset+3)));
				offset += 4;
			}
			break;

		case WCCP2_HERE_I_AM:
		case WCCP2_I_SEE_YOU:
		case WCCP2_REMOVAL_QUERY:
		case WCCP2_REDIRECT_ASSIGN:
		default:	/* assume unknown packets are v2 */
			length = dissect_wccp2_header(tvb, offset, wccp_tree);
			offset += 4;
			dissect_wccp2_info(tvb, offset, length, wccp_tree);
			break;
		}
	}
}

static void
dissect_hash_data(tvbuff_t *tvb, int offset, proto_tree *wccp_tree)
{
	proto_item *bucket_item;
	proto_tree *bucket_tree;
	proto_item *tf;
	proto_tree *field_tree;
	int i;
	guint8 bucket_info;
	int n;
	guint32 flags;

	proto_tree_add_item(wccp_tree, hf_hash_revision, tvb, offset, 4,
	    FALSE);
	offset += 4;

	bucket_item = proto_tree_add_text(wccp_tree, tvb, offset, 32,
	    "Hash information");
	bucket_tree = proto_item_add_subtree(bucket_item, ett_buckets);

	for (i = 0, n = 0; i < 32; i++) {
		bucket_info = tvb_get_guint8(tvb, offset);
		n = wccp_bucket_info(bucket_info, bucket_tree, n, tvb, offset);
		offset += 1;
	}
	flags = tvb_get_ntohl(tvb, offset);
	tf = proto_tree_add_text(wccp_tree, tvb, offset, 4,
	    "Flags: 0x%08X (%s)", flags,
	    ((flags & WCCP_U_FLAG) ?
	      "Hash information is historical" :
	      "Hash information is current"));
	field_tree = proto_item_add_subtree(tf, ett_flags);
	proto_tree_add_text(field_tree, tvb, offset, 4, "%s",
	    decode_boolean_bitfield(flags, WCCP_U_FLAG,
	      sizeof (flags)*8,
	      "Hash information is historical",
	      "Hash information is current"));
}

static void
dissect_web_cache_list_entry(tvbuff_t *tvb, int offset, int index,
    proto_tree *wccp_tree)
{
	proto_item *tl;
	proto_tree *list_entry_tree;

	tl = proto_tree_add_text(wccp_tree, tvb, offset, 4 + HASH_INFO_SIZE,
	    "Web-Cache List Entry(%d)", index);
	list_entry_tree = proto_item_add_subtree(tl, ett_cache_info);
	proto_tree_add_item(list_entry_tree, hf_cache_ip, tvb, offset, 4,
	    FALSE);
	dissect_hash_data(tvb, offset + 4, list_entry_tree);
}

/*
 * wccp_bucket_info()
 * takes an integer representing a "Hash Information" bitmap, and spits out
 * the corresponding proto_tree entries, returning the next bucket number.
 */
static int
wccp_bucket_info(guint8 bucket_info, proto_tree *bucket_tree, guint32 start,
    tvbuff_t *tvb, int offset)
{
	guint32 i;

	for(i = 0; i < 8; i++) {
		proto_tree_add_text(bucket_tree, tvb, offset, sizeof(bucket_info), "Bucket %3d: %s", start, (bucket_info & 1<<i ? "Assigned" : "Not Assigned") );
		start++;
	}
	return(start);
}

static gchar *
bucket_name(guint8 bucket)
{
	static gchar str[4][10+1];
	static gchar *cur;

	if (cur == &str[0][0])
		cur = &str[1][0];
	else if (cur == &str[1][0])
		cur = &str[2][0];
	else if (cur == &str[2][0])
		cur = &str[3][0];
	else
		cur = &str[0][0];
	if (bucket == 0xff)
		strcpy(cur, "Unassigned");
	else
		sprintf(cur, "%u", bucket);
	return cur;
}

static guint16
dissect_wccp2_header(tvbuff_t *tvb, int offset, proto_tree *wccp_tree)
{
	guint16 length;

	proto_tree_add_item(wccp_tree, hf_wccp_version, tvb, offset, 2,
	    FALSE);
	offset += 2;
	length = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(wccp_tree, tvb, offset, 2, "Length: %u",
	    length);
	return length;
}

static void
dissect_wccp2_info(tvbuff_t *tvb, int offset, guint16 length,
    proto_tree *wccp_tree)
{
	guint16 type;
	guint16 item_length;
	proto_item *ti;
	proto_tree *info_tree;
	gint ett;
	gboolean (*dissector)(tvbuff_t *, int, int, proto_tree *);

	while (length != 0) {
		type = tvb_get_ntohs(tvb, offset);
		item_length = tvb_get_ntohs(tvb, offset+2);

		switch (type) {

		case WCCP2_SECURITY_INFO:
			ett = ett_security_info;
			dissector = dissect_wccp2_security_info;
			break;

		case WCCP2_SERVICE_INFO:
			ett = ett_service_info;
			dissector = dissect_wccp2_service_info;
			break;

		case WCCP2_ROUTER_ID_INFO:
			ett = ett_router_identity_info;
			dissector = dissect_wccp2_router_identity_info;
			break;

		case WCCP2_WC_ID_INFO:
			ett = ett_wc_identity_info;
			dissector = dissect_wccp2_wc_identity_info;
			break;

		case WCCP2_RTR_VIEW_INFO:
			ett = ett_router_view_info;
			dissector = dissect_wccp2_router_view_info;
			break;

		case WCCP2_WC_VIEW_INFO:
			ett = ett_wc_view_info;
			dissector = dissect_wccp2_wc_view_info;
			break;

		case WCCP2_REDIRECT_ASSIGNMENT:
			ett = ett_router_assignment_info;
			dissector = dissect_wccp2_assignment_info;
			break;

		case WCCP2_QUERY_INFO:
			ett = ett_query_info;
			dissector = dissect_wccp2_router_query_info;
			break;

		case WCCP2_CAPABILITIES_INFO:
			ett = ett_capabilities_info;
			dissector = dissect_wccp2_capability_info;
			break;

		default:
			ett = ett_unknown_info;
			dissector = NULL;
			break;
		}

		ti = proto_tree_add_text(wccp_tree, tvb, offset, item_length + 4,
		    val_to_str(type, info_type_vals, "Unknown info type (%u)"));
		info_tree = proto_item_add_subtree(ti, ett);
		proto_tree_add_text(info_tree, tvb, offset, 2,
		    "Type: %s",
		    val_to_str(type, info_type_vals, "Unknown info type (%u)"));
		proto_tree_add_text(info_tree, tvb, offset+2, 2,
		    "Length: %u", item_length);
		offset += 4;
		length -= 4;

		/*
		 * XXX - pass in "length" and check for that as well.
		 */
		if (dissector != NULL) {
			if (!(*dissector)(tvb, offset, item_length, info_tree))
				return;	/* ran out of data */
		} else {
			proto_tree_add_text(info_tree, tvb, offset, item_length,
			    "Data: %u byte%s", item_length,
			    plurality(item_length, "", "s"));
		}
		offset += item_length;
		length -= item_length;
	}
}

#define SECURITY_INFO_LEN		4

#define WCCP2_NO_SECURITY		0
#define WCCP2_MD5_SECURITY		1

static gboolean
dissect_wccp2_security_info(tvbuff_t *tvb, int offset, int length,
    proto_tree *info_tree)
{
	guint32 security_option;

	if (length < SECURITY_INFO_LEN) {
		proto_tree_add_text(info_tree, tvb, offset, 0,
		    "Item length is %u, should be %u", length,
		    SECURITY_INFO_LEN);
		return TRUE;
	}

	security_option = tvb_get_ntohl(tvb, offset);
	switch (security_option) {

	case WCCP2_NO_SECURITY:
		proto_tree_add_text(info_tree, tvb, offset, 4,
		    "Security Option: None");
		break;

	case WCCP2_MD5_SECURITY:
		proto_tree_add_text(info_tree, tvb, offset, 4,
		    "Security Option: MD5");
		offset += 4;
		if (length > 4) {
			proto_tree_add_text(info_tree, tvb, offset,
			    length - 4, "MD5 checksum: %s",
			    tvb_bytes_to_str(tvb, offset, length - 4));
		}
		break;

	default:
		proto_tree_add_text(info_tree, tvb, offset, 4,
		    "Security Option: Unknown (%u)", security_option);
		break;
	}
	return TRUE;
}

#define SERVICE_INFO_LEN		(4+4+8*2)

#define	WCCP2_SERVICE_STANDARD		0
#define	WCCP2_SERVICE_DYNAMIC		1

/*
 * Service flags.
 */
#define	WCCP2_SI_SRC_IP_HASH		0x0001
#define	WCCP2_SI_DST_IP_HASH		0x0002
#define	WCCP2_SI_SRC_PORT_HASH		0x0004
#define	WCCP2_SI_DST_PORT_HASH		0x0008
#define	WCCP2_SI_PORTS_DEFINED		0x0010
#define	WCCP2_SI_PORTS_SOURCE		0x0020
#define	WCCP2_SI_SRC_IP_ALT_HASH	0x0100
#define	WCCP2_SI_DST_IP_ALT_HASH	0x0200
#define	WCCP2_SI_SRC_PORT_ALT_HASH	0x0400
#define	WCCP2_SI_DST_PORT_ALT_HASH	0x0800

static gboolean
dissect_wccp2_service_info(tvbuff_t *tvb, int offset, int length,
    proto_tree *info_tree)
{
	guint8 service_type;
	guint32 flags;
	proto_item *tf;
	proto_tree *field_tree;
	int i;

	if (length != SERVICE_INFO_LEN) {
		proto_tree_add_text(info_tree, tvb, offset, 0,
		    "Item length is %u, should be %u", length,
		    SERVICE_INFO_LEN);
		return TRUE;
	}

	service_type = tvb_get_guint8(tvb, offset);
	switch (service_type) {

	case WCCP2_SERVICE_STANDARD:
		proto_tree_add_text(info_tree, tvb, offset, 1,
		    "Service Type: Well-known service");
		proto_tree_add_text(info_tree, tvb, offset+1, 1,
		    "Service ID: %s",
		    val_to_str(tvb_get_guint8(tvb, offset+1), service_id_vals, 
			    "Unknown (0x%02X)"));

		break;

	case WCCP2_SERVICE_DYNAMIC:
		proto_tree_add_text(info_tree, tvb, offset, 1,
		    "Service Type: Dynamic service");
		proto_tree_add_text(info_tree, tvb, offset+1, 1,
		    "Service ID: %s",
		    val_to_str(tvb_get_guint8(tvb, offset+1), service_id_vals, 
			    "Unknown (0x%02X)"));
		proto_tree_add_text(info_tree, tvb, offset+2, 1,
		    "Priority: %u", tvb_get_guint8(tvb, offset+2));
		/*
		 * XXX - does "IP protocol identifier" mean this is a
		 * protocol type of the sort you get in IP headers?
		 * If so, we should get a table of those from the
		 * IP dissector, and use that.
		 */
		proto_tree_add_text(info_tree, tvb, offset+3, 1,
		    "Protocol: %u", tvb_get_guint8(tvb, offset+3));	/* IP protocol identifier */
		break;

	default:
		proto_tree_add_text(info_tree, tvb, offset, 1,
		    "Service Type: Unknown (%u)", service_type);
		break;
	}
	offset += 4;

	flags = tvb_get_ntohl(tvb, offset);
	tf = proto_tree_add_text(info_tree, tvb, offset, 4,
	    "Flags: 0x%08X", flags);
	field_tree = proto_item_add_subtree(tf, ett_service_flags);
	proto_tree_add_text(field_tree, tvb, offset, 4, "%s",
	    decode_boolean_bitfield(flags, WCCP2_SI_SRC_IP_HASH,
	      sizeof (flags)*8,
	      "Use source IP address in primary hash",
	      "Don't use source IP address in primary hash"));
	proto_tree_add_text(field_tree, tvb, offset, 4, "%s",
	    decode_boolean_bitfield(flags, WCCP2_SI_DST_IP_HASH,
	      sizeof (flags)*8,
	      "Use destination IP address in primary hash",
	      "Don't use destination IP address in primary hash"));
	proto_tree_add_text(field_tree, tvb, offset, 4, "%s",
	    decode_boolean_bitfield(flags, WCCP2_SI_SRC_PORT_HASH,
	      sizeof (flags)*8,
	      "Use source port in primary hash",
	      "Don't use source port in primary hash"));
	proto_tree_add_text(field_tree, tvb, offset, 4, "%s",
	    decode_boolean_bitfield(flags, WCCP2_SI_DST_PORT_HASH,
	      sizeof (flags)*8,
	      "Use destination port in primary hash",
	      "Don't use destination port in primary hash"));
	proto_tree_add_text(field_tree, tvb, offset, 4, "%s",
	    decode_boolean_bitfield(flags, WCCP2_SI_PORTS_DEFINED,
	      sizeof (flags)*8,
	      "Ports defined",
	      "Ports not defined"));
	if (flags & WCCP2_SI_PORTS_DEFINED) {
		proto_tree_add_text(field_tree, tvb, offset, 4, "%s",
		    decode_boolean_bitfield(flags, WCCP2_SI_PORTS_SOURCE,
		      sizeof (flags)*8,
		      "Ports refer to source port",
		      "Ports refer to destination port"));
	}
	proto_tree_add_text(field_tree, tvb, offset, 4, "%s",
	    decode_boolean_bitfield(flags, WCCP2_SI_SRC_IP_ALT_HASH,
	      sizeof (flags)*8,
	      "Use source IP address in secondary hash",
	      "Don't use source IP address in secondary hash"));
	proto_tree_add_text(field_tree, tvb, offset, 4, "%s",
	    decode_boolean_bitfield(flags, WCCP2_SI_DST_IP_ALT_HASH,
	      sizeof (flags)*8,
	      "Use destination IP address in secondary hash",
	      "Don't use destination IP address in secondary hash"));
	proto_tree_add_text(field_tree, tvb, offset, 4, "%s",
	    decode_boolean_bitfield(flags, WCCP2_SI_SRC_PORT_ALT_HASH,
	      sizeof (flags)*8,
	      "Use source port in secondary hash",
	      "Don't use source port in secondary hash"));
	proto_tree_add_text(field_tree, tvb, offset, 4, "%s",
	    decode_boolean_bitfield(flags, WCCP2_SI_DST_PORT_ALT_HASH,
	      sizeof (flags)*8,
	      "Use destination port in secondary hash",
	      "Don't use destination port in secondary hash"));
	offset += 4;

	if (flags & WCCP2_SI_PORTS_DEFINED) {
		for (i = 0; i < 8; i++) {
			proto_tree_add_text(info_tree, tvb, offset, 2,
			    "Port %d: %u", i, tvb_get_ntohs(tvb, offset));
			offset += 2;
		}
	}

	return TRUE;
}

#define	ROUTER_ID_INFO_MIN_LEN		(8+4+4)

static void
dissect_wccp2_router_identity_element(tvbuff_t *tvb, int offset,
    proto_tree *tree)
{
	proto_tree_add_text(tree, tvb, offset, 4,
	    "IP Address: %s", ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	proto_tree_add_text(tree, tvb, offset + 4, 4,
	    "Receive ID: %u", tvb_get_ntohl(tvb, offset + 4));
}

static gboolean
dissect_wccp2_router_identity_info(tvbuff_t *tvb, int offset, int length,
    proto_tree *info_tree)
{
	guint32 n_received_from;
	guint i;
	proto_item *te;
	proto_tree *element_tree;

	if (length < ROUTER_ID_INFO_MIN_LEN) {
		proto_tree_add_text(info_tree, tvb, offset, 0,
		    "Item length is %u, should be >= %u", length,
		    ROUTER_ID_INFO_MIN_LEN);
		return TRUE;
	}

	te = proto_tree_add_text(info_tree, tvb, offset, 8,
	    "Router Identity Element: IP address %s",
	    ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	element_tree = proto_item_add_subtree(te,
	    ett_router_identity_element);
	dissect_wccp2_router_identity_element(tvb, offset, element_tree);
	offset += 8;

	proto_tree_add_text(info_tree, tvb, offset, 4,
	    "Sent To IP Address: %s", ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	offset += 4;

	n_received_from = tvb_get_ntohl(tvb, offset);
	proto_tree_add_text(info_tree, tvb, offset, 4,
	    "Number of Received From IP addresses: %u", n_received_from);
	offset += 4;

	for (i = 0; i < n_received_from; i++) {
		proto_tree_add_text(info_tree, tvb, offset, 4,
		    "Received From IP Address %d: %s", i,
		    ip_to_str(tvb_get_ptr(tvb, offset, 4)));
		offset += 4;
	}

	return TRUE;
}

#define	WC_ID_INFO_LEN			(4+4+8*4+4)

static gboolean
dissect_wccp2_web_cache_identity_element(tvbuff_t *tvb, int offset,
    proto_tree *tree)
{
	proto_item *bucket_item;
	proto_tree *bucket_tree;
	proto_item *tf;
	proto_tree *field_tree;
	guint16 flags;
	int i;
	guint8 bucket_info;
	int n;

	proto_tree_add_text(tree, tvb, offset, 4,
	    "Web-Cache IP Address: %s", ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	offset += 4;

	proto_tree_add_text(tree, tvb, offset, 2,
	    "Hash Revision %u", tvb_get_ntohs(tvb, offset));
	offset += 2;

	flags = tvb_get_ntohs(tvb, offset);
	tf = proto_tree_add_text(tree, tvb, offset, 2,
	    "Flags: 0x%04X (%s)", flags,
	    ((flags & 0x8000) ?
	      "Hash information is historical" :
	      "Hash information is current"));
	field_tree = proto_item_add_subtree(tf, ett_flags);
	proto_tree_add_text(field_tree, tvb, offset, 2, "%s",
	    decode_boolean_bitfield(flags, 0x8000,
	      sizeof (flags)*8,
	      "Hash information is historical",
	      "Hash information is current"));
	offset += 2;

	bucket_item = proto_tree_add_text(tree, tvb, offset, 8*4,
	    "Hash information");
	bucket_tree = proto_item_add_subtree(bucket_item, ett_buckets);
	for (i = 0, n = 0; i < 32; i++) {
		bucket_info = tvb_get_guint8(tvb, offset);
		n = wccp_bucket_info(bucket_info, bucket_tree, n, tvb, offset);
		offset += 1;
	}

	proto_tree_add_text(tree, tvb, offset, 2,
	    "Assignment Weight: %u", tvb_get_ntohs(tvb, offset));
	offset += 2;

	proto_tree_add_text(tree, tvb, offset, 2,
	    "Status: 0x%04X", tvb_get_ntohs(tvb, offset));
	offset += 2;

	return TRUE;
}

static gboolean
dissect_wccp2_wc_identity_info(tvbuff_t *tvb, int offset, int length,
    proto_tree *info_tree)
{
	proto_item *te;
	proto_tree *element_tree;

	if (length != WC_ID_INFO_LEN) {
		proto_tree_add_text(info_tree, tvb, offset, 0,
		    "Item length is %u, should be %u", length, WC_ID_INFO_LEN);
		return TRUE;
	}

	te = proto_tree_add_text(info_tree, tvb, offset, 4+2+2+32+2+2,
	    "Web-Cache Identity Element: IP address %s",
	    ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	element_tree = proto_item_add_subtree(te, ett_wc_identity_element);
	if (!dissect_wccp2_web_cache_identity_element(tvb, offset,
	    element_tree))
		return FALSE;	/* ran out of data */

	return TRUE;
}

#define	ROUTER_VIEW_INFO_MIN_LEN	(4+8+4)

static void
dissect_wccp2_assignment_key(tvbuff_t *tvb, int offset,
    proto_tree *info_tree)
{
	proto_tree_add_text(info_tree, tvb, offset, 4,
	    "Assignment Key IP Address: %s",
	    ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	proto_tree_add_text(info_tree, tvb, offset + 4, 4,
	    "Assignment Key Change Number: %u", tvb_get_ntohl(tvb, offset + 4));
}

static gboolean
dissect_wccp2_router_view_info(tvbuff_t *tvb, int offset, int length,
    proto_tree *info_tree)
{
	guint32 n_routers;
	guint32 n_web_caches;
	guint i;
	proto_item *te;
	proto_tree *element_tree;

	if (length < ROUTER_VIEW_INFO_MIN_LEN) {
		proto_tree_add_text(info_tree, tvb, offset, 0,
		    "Item length is %u, should be >= %u", length,
		    ROUTER_VIEW_INFO_MIN_LEN);
		return TRUE;
	}

	proto_tree_add_text(info_tree, tvb, offset, 4,
	    "Member Change Number: %u", tvb_get_ntohl(tvb, offset));
	offset += 4;

	dissect_wccp2_assignment_key(tvb, offset, info_tree);
	offset += 8;

	n_routers = tvb_get_ntohl(tvb, offset);
	proto_tree_add_text(info_tree, tvb, offset, 4,
	    "Number of Routers: %u", n_routers);
	offset += 4;

	for (i = 0; i < n_routers; i++) {
		proto_tree_add_text(info_tree, tvb, offset, 4,
		    "Router %d IP Address: %s", i,
		    ip_to_str(tvb_get_ptr(tvb, offset, 4)));
		offset += 4;
	}

	n_web_caches = tvb_get_ntohl(tvb, offset);
	proto_tree_add_text(info_tree, tvb, offset, 4,
	    "Number of Web Caches: %u", n_web_caches);
	offset += 4;

	for (i = 0; i < n_web_caches; i++) {
		te = proto_tree_add_text(info_tree, tvb, offset, WC_ID_INFO_LEN,
		    "Web-Cache Identity Element %d: IP address %s", i,
		    ip_to_str(tvb_get_ptr(tvb, offset, 4)));
		element_tree = proto_item_add_subtree(te,
		    ett_wc_identity_element);
		if (!dissect_wccp2_web_cache_identity_element(tvb,
		    offset, element_tree))
			return FALSE;	/* ran out of data */
		offset += WC_ID_INFO_LEN;
	}

	return TRUE;
}

#define	WC_VIEW_INFO_MIN_LEN		(4+4)

static gboolean
dissect_wccp2_wc_view_info(tvbuff_t *tvb, int offset, int length,
    proto_tree *info_tree)
{
	guint32 n_routers;
	guint32 n_web_caches;
	guint i;
	proto_item *te;
	proto_tree *element_tree;

	if (length < WC_VIEW_INFO_MIN_LEN) {
		proto_tree_add_text(info_tree, tvb, offset, 0,
		    "Item length is %u, should be >= %u", length,
		    WC_VIEW_INFO_MIN_LEN);
		return TRUE;
	}

	proto_tree_add_text(info_tree, tvb, offset, 4,
	    "Change Number: %u", tvb_get_ntohl(tvb, offset));
	offset += 4;

	n_routers = tvb_get_ntohl(tvb, offset);
	proto_tree_add_text(info_tree, tvb, offset, 4,
	    "Number of Routers: %u", n_routers);
	offset += 4;

	for (i = 0; i < n_routers; i++) {
		te = proto_tree_add_text(info_tree, tvb, offset, 8,
		    "Router %d Identity Element: IP address %s", i,
		    ip_to_str(tvb_get_ptr(tvb, offset, 4)));
		element_tree = proto_item_add_subtree(te,
		    ett_router_identity_element);
		dissect_wccp2_router_identity_element(tvb, offset, element_tree);
		offset += 8;
	}

	n_web_caches = tvb_get_ntohl(tvb, offset);
	proto_tree_add_text(info_tree, tvb, offset, 4,
	    "Number of Web Caches: %u", n_web_caches);
	offset += 4;

	for (i = 0; i < n_web_caches; i++) {
		proto_tree_add_text(info_tree, tvb, offset, 4,
		    "Web-Cache %d: IP address %s", i,
		    ip_to_str(tvb_get_ptr(tvb, offset, 4)));
		offset += 4;
	}
	
	return TRUE;
}

#define	ASSIGNMENT_INFO_MIN_LEN		(8+4)

static void
dissect_wccp2_router_assignment_element(tvbuff_t *tvb, int offset,
    proto_tree *tree)
{
	proto_tree_add_text(tree, tvb, offset, 4,
	    "IP Address: %s", ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	proto_tree_add_text(tree, tvb, offset + 4, 4,
	    "Receive ID: %u", tvb_get_ntohl(tvb, offset + 4));
	proto_tree_add_text(tree, tvb, offset + 8, 4,
	    "Change Number: %u", tvb_get_ntohl(tvb, offset + 8));
}

static gchar *
assignment_bucket_name(guint8 bucket)
{
	static gchar str[4][10+1];
	static gchar *cur;

	if (cur == &str[0][0])
		cur = &str[1][0];
	else if (cur == &str[1][0])
		cur = &str[2][0];
	else if (cur == &str[2][0])
		cur = &str[3][0];
	else
		cur = &str[0][0];
	if (bucket == 0xff)
		strcpy(cur, "Unassigned");
	else {
		sprintf(cur, "%u%s", bucket >> 1,
		    (bucket & 0x01) ? " (Alt)" : "");
	}
	return cur;
}

static gboolean
dissect_wccp2_assignment_info(tvbuff_t *tvb, int offset, int length,
    proto_tree *info_tree)
{
	guint32 n_routers;
	guint32 n_web_caches;
	guint i;
	proto_item *te;
	proto_tree *element_tree;

	if (length < ASSIGNMENT_INFO_MIN_LEN) {
		proto_tree_add_text(info_tree, tvb, offset, 0,
		    "Item length is %u, should be >= %u", length,
		    ASSIGNMENT_INFO_MIN_LEN);
		return TRUE;
	}

	dissect_wccp2_assignment_key(tvb, offset, info_tree);
	offset += 8;

	n_routers = tvb_get_ntohl(tvb, offset);
	proto_tree_add_text(info_tree, tvb, offset, 4,
	    "Number of Routers: %u", n_routers);
	offset += 4;

	for (i = 0; i < n_routers; i++) {
		te = proto_tree_add_text(info_tree, tvb, offset, 4,
		    "Router %d Assignment Element: IP address %s", i,
		    ip_to_str(tvb_get_ptr(tvb, offset, 4)));
		element_tree = proto_item_add_subtree(te,
		    ett_router_assignment_element);
		dissect_wccp2_router_assignment_element(tvb, offset,
		    element_tree);
		offset += 12;
	}

	n_web_caches = tvb_get_ntohl(tvb, offset);
	proto_tree_add_text(info_tree, tvb, offset, 4,
	    "Number of Web Caches: %u", n_web_caches);
	offset += 4;

	for (i = 0; i < n_web_caches; i++) {
		proto_tree_add_text(info_tree, tvb, offset, 4,
		    "Web-Cache %d: IP address %s", i,
		    ip_to_str(tvb_get_ptr(tvb, offset, 4)));
		offset += 4;
	}

	for (i = 0; i < 256; i += 4) {
		proto_tree_add_text(info_tree, tvb, offset, 4,
		    "Buckets %d - %d: %10s %10s %10s %10s",
		    i, i + 3,
		    assignment_bucket_name(tvb_get_guint8(tvb, offset)),
		    assignment_bucket_name(tvb_get_guint8(tvb, offset+1)),
		    assignment_bucket_name(tvb_get_guint8(tvb, offset+2)),
		    assignment_bucket_name(tvb_get_guint8(tvb, offset+3)));
		offset += 4;
	}

	return TRUE;
}

#define	QUERY_INFO_LEN			(4+4+4+4)

static gboolean
dissect_wccp2_router_query_info(tvbuff_t *tvb, int offset, int length,
    proto_tree *info_tree)
{
	if (length != QUERY_INFO_LEN) {
		proto_tree_add_text(info_tree, tvb, offset, 0,
		    "Item length is %u, should be %u", length, QUERY_INFO_LEN);
		return TRUE;
	}

	proto_tree_add_text(info_tree, tvb, offset, 4,
	    "Router IP Address: %s", ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	offset += 4;

	proto_tree_add_text(info_tree, tvb, offset, 4,
	    "Receive ID: %u", tvb_get_ntohl(tvb, offset));
	offset += 4;

	proto_tree_add_text(info_tree, tvb, offset, 4,
	    "Sent To IP Address: %s", ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	offset += 4;

	proto_tree_add_text(info_tree, tvb, offset, 4,
	    "Target IP Address: %s", ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	offset += 4;

	return TRUE;
}

#define WCCP2_FORWARDING_METHOD         0x01
#define WCCP2_ASSIGNMENT_METHOD         0x02
#define WCCP2_PACKET_RETURN_METHOD      0x03

static const value_string capability_type_vals[] = {
	{ WCCP2_FORWARDING_METHOD,    "Forwarding Method" },
	{ WCCP2_ASSIGNMENT_METHOD,    "Assignment Method" },
	{ WCCP2_PACKET_RETURN_METHOD, "Return Method" },
	{ 0,                          NULL }
};

#define WCCP2_FORWARDING_METHOD_GRE	0x00000001
#define WCCP2_FORWARDING_METHOD_L2	0x00000002

static const capability_flag forwarding_method_flags[] = {
	{ WCCP2_FORWARDING_METHOD_GRE,
	  "IP-GRE", "GRE-encapsulated" },
	{ WCCP2_FORWARDING_METHOD_L2,
	  "L2", "L2 rewrite" },
	{ 0, 
	  NULL, NULL }
};

#define WCCP2_ASSIGNMENT_METHOD_HASH    0x00000001
#define WCCP2_ASSIGNMENT_METHOD_MASK    0x00000002

static const capability_flag assignment_method_flags[] = {
	{ WCCP2_ASSIGNMENT_METHOD_HASH, "Hash", "Hash" },
	{ WCCP2_ASSIGNMENT_METHOD_MASK, "Mask", "Mask" },
	{ 0,                            NULL,   NULL }
};

#define WCCP2_PACKET_RETURN_METHOD_GRE  0x00000001
#define WCCP2_PACKET_RETURN_METHOD_L2   0x00000002

static const capability_flag packet_return_method_flags[] = {
	{ WCCP2_PACKET_RETURN_METHOD_GRE,
	  "IP-GRE", "GRE-encapsulated" },
	{ WCCP2_PACKET_RETURN_METHOD_L2,
	  "L2", "L2 rewrite" },
	{ 0, 
	  NULL, NULL }
};

static gboolean
dissect_wccp2_capability_info(tvbuff_t *tvb, int offset, int length,
    proto_tree *info_tree)
{
	guint16 capability_type;
	guint16 capability_len;
	int curr_offset;
	proto_item *te;
	proto_tree *element_tree;

	for (curr_offset = offset; curr_offset < (length + offset);
	    curr_offset += capability_len + 4) {
		capability_type = tvb_get_ntohs(tvb, curr_offset);
		capability_len = tvb_get_ntohs(tvb, curr_offset + 2);
		te = proto_tree_add_text(info_tree, tvb, curr_offset,
		    capability_len, "%s",
		    val_to_str(capability_type,
		      capability_type_vals, "Unknown Capability Element (0x%08X)"));
		element_tree = proto_item_add_subtree(te,
		    ett_capability_element);

		proto_tree_add_text(element_tree, tvb, curr_offset, 2,
		    "Type: %s",
		    val_to_str(capability_type,
		      capability_type_vals, "Unknown (0x%08X)"));

		if (capability_len < 4) {
			proto_tree_add_text(element_tree, tvb, curr_offset+2, 2,
			    "Length: %u (illegal, must be >= 4)",
			    capability_len);
			break;
		}
		proto_tree_add_text(element_tree, tvb, curr_offset+2, 2,
		    "Length: %u", capability_len);

		switch (capability_type) {

		case WCCP2_FORWARDING_METHOD:
			dissect_32_bit_capability_flags(tvb, curr_offset,
			    capability_len, ett_capability_forwarding_method,
			    forwarding_method_flags, element_tree);
			break;

		case WCCP2_ASSIGNMENT_METHOD:
			dissect_32_bit_capability_flags(tvb, curr_offset,
			    capability_len, ett_capability_assignment_method,
			    assignment_method_flags, element_tree);
			break;

		case WCCP2_PACKET_RETURN_METHOD:
			dissect_32_bit_capability_flags(tvb, curr_offset,
			    capability_len, ett_capability_return_method,
			    packet_return_method_flags, element_tree);
			break;

		default:
			proto_tree_add_text(element_tree, tvb,
			    curr_offset+4, capability_len-4,
			    "Value: %s",
			    tvb_bytes_to_str(tvb, curr_offset+4, capability_len-4));
			break;
		}

	}
	return TRUE;
}

static void
dissect_32_bit_capability_flags(tvbuff_t *tvb, int curr_offset,
    guint16 capability_len, gint ett, const capability_flag *flags,
    proto_tree *element_tree)
{
	guint32 capability_val;
	proto_item *tm;
	proto_tree *method_tree;
	int i;
	char flags_string[128+1];
	char *p;
	int space_left;
	char buf[1025];

	if (capability_len != 4) {
		proto_tree_add_text(element_tree, tvb,
		    curr_offset+4, capability_len-4,
		    "Illegal length (must be 4)");
		return;
	}

	capability_val = tvb_get_ntohl(tvb, curr_offset + 4);
	flags_string[0] = '\0';
	p = &flags_string[0];
	space_left = sizeof flags_string;
	for (i = 0; flags[i].short_name != NULL; i++) {
		if (capability_val & flags[i].value) {
			if (p != &flags_string[0]) {
				snprintf(p, space_left, ",");
				p = &flags_string[strlen(flags_string)];
			}
			snprintf(p, space_left, "%s", flags[i].short_name);
			p = &flags_string[strlen(flags_string)];
		}
	}
	tm = proto_tree_add_text(element_tree, tvb, curr_offset+4, 4,
	    "Value: 0x%08X (%s)", capability_val, flags_string);
	method_tree = proto_item_add_subtree(tm, ett);
	for (i = 0; flags[i].long_name != NULL; i++) {
		p = decode_bitfield_value(buf, capability_val,
		      flags[i].value, 32);
		strcpy(p, flags[i].long_name);
		strcat(p, ": ");
		if (capability_val & flags[i].value)
		    strcat(p, "Supported");
		else
		    strcat(p, "Not supported");
		proto_tree_add_text(method_tree, tvb, curr_offset+4, 4,
		    "%s", buf);
	}
}

void
proto_register_wccp(void)
{
	static hf_register_info hf[] = {
		{ &hf_wccp_message_type,
			{ "WCCP Message Type", "wccp.message", FT_UINT32, BASE_DEC, VALS(wccp_type_vals), 0x0,
				"The WCCP message that was sent", HFILL }
		},
		{ &hf_wccp_version, 
			{ "WCCP Version", "wccp.version", FT_UINT32, BASE_HEX, VALS(wccp_version_val), 0x0,
				"The WCCP version", HFILL }
		},
		{ &hf_hash_revision,
			{ "Hash Revision", "wccp.hash_revision", FT_UINT32, BASE_DEC, 0x0, 0x0,
				"The cache hash revision", HFILL }
		},
		{ &hf_change_num,
			{ "Change Number", "wccp.change_num", FT_UINT32, BASE_DEC, 0x0, 0x0,
				"The Web-Cache list entry change number", HFILL }
		},
		{ &hf_recvd_id,
			{ "Received ID", "wccp.recvd_id", FT_UINT32, BASE_DEC, 0x0, 0x0,
				"The number of I_SEE_YOU's that have been sent", HFILL }
		},
		{ &hf_cache_ip,
			{ "Web Cache IP address", "wccp.cache_ip", FT_IPv4, BASE_NONE, NULL, 0x0,
				"The IP address of a Web cache", HFILL }
		},
	};
	static gint *ett[] = {
		&ett_wccp,
		&ett_cache_count,
		&ett_buckets,
		&ett_flags,
		&ett_cache_info,
		&ett_security_info,
		&ett_service_info,
		&ett_service_flags,
		&ett_router_identity_element,
		&ett_router_identity_info,
		&ett_wc_identity_element,
		&ett_wc_identity_info,
		&ett_router_view_info,
		&ett_wc_view_info,
		&ett_query_info,
		&ett_router_assignment_element,
		&ett_router_assignment_info,
		&ett_capabilities_info,
		&ett_capability_element,
		&ett_capability_forwarding_method,
		&ett_capability_assignment_method,
		&ett_capability_return_method,
		&ett_unknown_info,
	};

	proto_wccp = proto_register_protocol("Web Cache Coordination Protocol",
	    "WCCP", "wccp");
	proto_register_field_array(proto_wccp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_wccp(void)
{
	dissector_handle_t wccp_handle;

	wccp_handle = create_dissector_handle(dissect_wccp, proto_wccp);
	dissector_add("udp.port", UDP_PORT_WCCP, wccp_handle);
}
