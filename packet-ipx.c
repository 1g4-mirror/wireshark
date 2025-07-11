/* packet-ipx.c
 * Routines for NetWare's IPX
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * $Id: packet-ipx.c,v 1.101 2002/01/24 09:20:48 guy Exp $
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

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include "packet-ipx.h"
#include <epan/resolv.h>
#include "etypes.h"
#include "ppptypes.h"
#include "llcsaps.h"
#include "aftypes.h"

/* The information in this module (IPX, SPX, NCP) comes from:
	NetWare LAN Analysis, Second Edition
	Laura A. Chappell and Dan E. Hakes
	(c) 1994 Novell, Inc.
	Novell Press, San Jose.
	ISBN: 0-7821-1362-1

  And from the ncpfs source code by Volker Lendecke

*/
	
static int proto_ipx = -1;
static int hf_ipx_checksum = -1;
static int hf_ipx_len = -1;
static int hf_ipx_hops = -1;
static int hf_ipx_packet_type = -1;
static int hf_ipx_dnet = -1;
static int hf_ipx_dnode = -1;
static int hf_ipx_dsocket = -1;
static int hf_ipx_snet = -1;
static int hf_ipx_snode = -1;
static int hf_ipx_ssocket = -1;

static gint ett_ipx = -1;

static dissector_table_t ipx_type_dissector_table;
static dissector_table_t ipx_socket_dissector_table;

static int proto_spx = -1;
static int hf_spx_connection_control = -1;
static int hf_spx_datastream_type = -1;
static int hf_spx_src_id = -1;
static int hf_spx_dst_id = -1;
static int hf_spx_seq_nr = -1;
static int hf_spx_ack_nr = -1;
static int hf_spx_all_nr = -1;

static gint ett_spx = -1;

static int proto_ipxrip = -1;
static int hf_ipxrip_request = -1;
static int hf_ipxrip_response = -1;

static gint ett_ipxrip = -1;

static int proto_sap = -1;
static int hf_sap_request = -1;
static int hf_sap_response = -1;

static gint ett_ipxsap = -1;
static gint ett_ipxsap_server = -1;

static gint ett_ipxmsg = -1;
static int proto_ipxmsg = -1;
static int hf_msg_conn = -1;
static int hf_msg_sigchar = -1;

static dissector_handle_t data_handle;

static void
dissect_spx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void
dissect_ipxrip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void
dissect_ipxsap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void
dissect_ipxmsg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

#define UDP_PORT_IPX    213		/* RFC 1234 */

#define IPX_HEADER_LEN	30		/* It's *always* 30 bytes */

/* ================================================================= */
/* IPX                                                               */
/* ================================================================= */
static const value_string ipx_socket_vals[] = {
	{ IPX_SOCKET_PING_CISCO,		"CISCO PING" },
	{ IPX_SOCKET_NCP,			"NCP" },
	{ IPX_SOCKET_SAP,			"SAP" },
	{ IPX_SOCKET_IPXRIP,			"RIP" },
	{ IPX_SOCKET_NETBIOS,			"NetBIOS" },
	{ IPX_SOCKET_DIAGNOSTIC,		"Diagnostic" },
	{ IPX_SOCKET_SERIALIZATION,		"Serialization" },
	{ IPX_SOCKET_NWLINK_SMB_SERVER,		"NWLink SMB Server" },
	{ IPX_SOCKET_NWLINK_SMB_NAMEQUERY,	"NWLink SMB Name Query" },
	{ IPX_SOCKET_NWLINK_SMB_REDIR,		"NWLink SMB Redirector" },
	{ IPX_SOCKET_NWLINK_SMB_MAILSLOT,	"NWLink SMB Mailslot Datagram" },
	{ IPX_SOCKET_NWLINK_SMB_MESSENGER,	"NWLink SMB Messenger" },
	{ IPX_SOCKET_NWLINK_SMB_BROWSE,		"NWLink SMB Browse" },
	{ IPX_SOCKET_ATTACHMATE_GW,		"Attachmate Gateway" },
	{ IPX_SOCKET_IPX_MESSAGE,		"IPX Message" },
	{ IPX_SOCKET_SNMP_AGENT,		"SNMP Agent" },
	{ IPX_SOCKET_SNMP_SINK,			"SNMP Sink" },
	{ IPX_SOCKET_PING_NOVELL,		"Novell PING" },
	{ IPX_SOCKET_UDP_TUNNEL,		"UDP Tunnel" },
	{ IPX_SOCKET_TCP_TUNNEL,		"TCP Tunnel" },
	{ IPX_SOCKET_TCP_TUNNEL,		"TCP Tunnel" },
	{ IPX_SOCKET_ADSM,			"ADSM" },
	{ IPX_SOCKET_EIGRP,			"Cisco EIGRP for IPX" },
	{ IPX_SOCKET_WIDE_AREA_ROUTER,		"Wide Area Router" },
	{ 0xE885,				"NT Server-RPC/GW" },
	{ 0x400C,				"HP LaserJet/QuickSilver" },
	{ 0x907B,				"SMS Testing and Development" },
	{ 0x8F83,				"Powerchute UPS Monitoring" },
	{ 0x4006,				"Netware Directory Server" },
	{ 0x8104,				"Netware 386" },
	{ 0x0000,				NULL }
};

static const char*
socket_text(guint16 socket)
{
	return val_to_str(socket, ipx_socket_vals, "Unknown");
}

static const value_string ipx_packet_type_vals[] = {
	{ IPX_PACKET_TYPE_IPX,		"IPX" },
	{ IPX_PACKET_TYPE_RIP,		"RIP" },
	{ IPX_PACKET_TYPE_ECHO,		"Echo" },
	{ IPX_PACKET_TYPE_ERROR,	"Error" },
	{ IPX_PACKET_TYPE_PEP,		"PEP" }, /* Packet Exchange Packet */
	{ IPX_PACKET_TYPE_SPX,		"SPX" },
	{ 16,				"Experimental Protocol" },
	{ IPX_PACKET_TYPE_NCP,		"NCP" },
	{ 18,				"Experimental Protocol" },
	{ 19,				"Experimental Protocol" },
	{ IPX_PACKET_TYPE_WANBCAST,	"NetBIOS Broadcast" },
	{ 21,				"Experimental Protocol" },
	{ 22,				"Experimental Protocol" },
	{ 23,				"Experimental Protocol" },
	{ 24,				"Experimental Protocol" },
	{ 25,				"Experimental Protocol" },
	{ 26,				"Experimental Protocol" },
	{ 27,				"Experimental Protocol" },
	{ 28,				"Experimental Protocol" },
	{ 29,				"Experimental Protocol" },
	{ 30,				"Experimental Protocol" },
	{ 31,				"Experimental Protocol" },
	{ 0,				NULL }
};

static const value_string ipxmsg_sigchar_vals[] = {
	{ '?', "Poll inactive station" },
	{ 0, NULL }
};

void
capture_ipx(const u_char *pd, int offset, int len, packet_counts *ld)
{
	ld->ipx++;
}

static void
dissect_ipx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t	*next_tvb;

	proto_tree	*ipx_tree;
	proto_item	*ti;

	const guint8	*src_net_node, *dst_net_node;

	guint8		ipx_type, ipx_hops;
	guint16		ipx_length;

	guint16		ipx_dsocket, ipx_ssocket;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPX");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	/* Calculate here for use in pinfo and in tree */
	ipx_dsocket	= tvb_get_ntohs(tvb, 16);
	ipx_ssocket	= tvb_get_ntohs(tvb, 28);
	ipx_type	= tvb_get_guint8(tvb, 5);
	ipx_length	= tvb_get_ntohs(tvb, 2);

	/* Adjust the tvbuff length to include only the IPX datagram. */
	set_actual_length(tvb, pinfo, ipx_length);

	src_net_node = tvb_get_ptr(tvb, 18, 10);
	dst_net_node = tvb_get_ptr(tvb, 6,  10);

	SET_ADDRESS(&pinfo->net_src,	AT_IPX, 10, src_net_node);
	SET_ADDRESS(&pinfo->src,	AT_IPX, 10, src_net_node);
	SET_ADDRESS(&pinfo->net_dst,	AT_IPX, 10, dst_net_node);
	SET_ADDRESS(&pinfo->dst,	AT_IPX, 10, dst_net_node);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s (0x%04x)",
				socket_text(ipx_dsocket), ipx_dsocket);

	if (tree) {

		ti = proto_tree_add_item(tree, proto_ipx, tvb, 0, IPX_HEADER_LEN, FALSE);
		ipx_tree = proto_item_add_subtree(ti, ett_ipx);

		proto_tree_add_item(ipx_tree, hf_ipx_checksum, tvb, 0, 2, FALSE);
		proto_tree_add_uint_format(ipx_tree, hf_ipx_len, tvb, 2, 2, ipx_length,
			"Length: %d bytes", ipx_length);
		ipx_hops = tvb_get_guint8(tvb, 4);
		proto_tree_add_uint_format(ipx_tree, hf_ipx_hops, tvb, 4, 1, ipx_hops,
			"Transport Control: %d hops", ipx_hops);
		proto_tree_add_uint(ipx_tree, hf_ipx_packet_type, tvb, 5, 1, ipx_type);

		/* Destination */
		proto_tree_add_item(ipx_tree, hf_ipx_dnet, tvb, 6, 4, FALSE);
		proto_tree_add_item(ipx_tree, hf_ipx_dnode, tvb, 10, 6, FALSE);
		proto_tree_add_uint(ipx_tree, hf_ipx_dsocket, tvb, 16, 2,
			ipx_dsocket);

		/* Source */
		proto_tree_add_item(ipx_tree, hf_ipx_snet, tvb, 18, 4, FALSE);
		proto_tree_add_item(ipx_tree, hf_ipx_snode, tvb, 22, 6, FALSE);
		proto_tree_add_uint(ipx_tree, hf_ipx_ssocket, tvb, 28, 2,
			ipx_ssocket);
	}

	/* Make the next tvbuff */
	next_tvb = tvb_new_subset(tvb, IPX_HEADER_LEN, -1, -1);

	if (dissector_try_port(ipx_type_dissector_table, ipx_type, next_tvb,
	    pinfo, tree))
		return;

	/*
	 * Let the subdissector know what type of IPX packet this is.
	 */
	pinfo->ipxptype = ipx_type;

	if (dissector_try_port(ipx_socket_dissector_table, ipx_dsocket,
	    next_tvb, pinfo, tree))
		return;
	if (dissector_try_port(ipx_socket_dissector_table, ipx_ssocket,
	    next_tvb, pinfo, tree))
		return;
	call_dissector(data_handle,next_tvb, pinfo, tree);
}


/* ================================================================= */
/* SPX                                                               */
/* ================================================================= */
static const char*
spx_conn_ctrl(guint8 ctrl)
{
	const char *p;

	static const value_string conn_vals[] = {
		{ 0x10, "End-of-Message" },
		{ 0x20, "Attention" },
		{ 0x40, "Acknowledgment Required"},
		{ 0x80, "System Packet"},
		{ 0x00, NULL }
	};

	p = match_strval(ctrl, conn_vals);

	if (p) {
		return p;
	}
	else {
		return "Unknown";
	}
}

static const char*
spx_datastream(guint8 type)
{
	switch (type) {
		case 0xfe:
			return "End-of-Connection";
		case 0xff:
			return "End-of-Connection Acknowledgment";
		default:
			return "Client-Defined";
	}
}

#define SPX_HEADER_LEN	12

static void
dissect_spx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*spx_tree;
	proto_item	*ti;
	tvbuff_t	*next_tvb;

	guint8		conn_ctrl;
	guint8		datastream_type;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "SPX");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "SPX");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_spx, tvb, 0, SPX_HEADER_LEN, FALSE);
		spx_tree = proto_item_add_subtree(ti, ett_spx);

		conn_ctrl = tvb_get_guint8(tvb, 0);
		proto_tree_add_uint_format(spx_tree, hf_spx_connection_control, tvb,
					   0, 1, conn_ctrl,
					   "Connection Control: %s (0x%02X)",
					   spx_conn_ctrl(conn_ctrl), conn_ctrl);

		datastream_type = tvb_get_guint8(tvb, 1);
		proto_tree_add_uint_format(spx_tree, hf_spx_datastream_type, tvb,
					   1, 1, datastream_type,
					   "Datastream Type: %s (0x%02X)",
					   spx_datastream(datastream_type), datastream_type);

		proto_tree_add_item(spx_tree, hf_spx_src_id, tvb,  2, 2, FALSE);
		proto_tree_add_item(spx_tree, hf_spx_dst_id, tvb,  4, 2, FALSE);
		proto_tree_add_item(spx_tree, hf_spx_seq_nr, tvb,  6, 2, FALSE);
		proto_tree_add_item(spx_tree, hf_spx_ack_nr, tvb,  8, 2, FALSE);
		proto_tree_add_item(spx_tree, hf_spx_all_nr, tvb, 10, 2, FALSE);

		next_tvb = tvb_new_subset(tvb, SPX_HEADER_LEN, -1, -1);
		call_dissector(data_handle,next_tvb, pinfo, tree);
	}
}

/* ================================================================= */
/* IPX Message                                                       */
/* ================================================================= */
static void
dissect_ipxmsg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*msg_tree;
	proto_item	*ti;
	guint8		conn_number, sig_char;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPX MSG");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	conn_number = tvb_get_guint8(tvb, 0);
	sig_char = tvb_get_guint8(tvb, 1);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, 
			"%s, Connection %d", 
			val_to_str(sig_char, ipxmsg_sigchar_vals, "Unknown Signature Char"), conn_number);
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_ipxmsg, tvb, 0, -1, FALSE);
		msg_tree = proto_item_add_subtree(ti, ett_ipxmsg);

		proto_tree_add_uint(msg_tree, hf_msg_conn, tvb, 0, 1, conn_number);
		proto_tree_add_uint(msg_tree, hf_msg_sigchar, tvb, 1, 1, sig_char);
	}
}


/* ================================================================= */
/* IPX RIP                                                           */
/* ================================================================= */
static void
dissect_ipxrip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*rip_tree;
	proto_item	*ti;
	guint16		operation;
	struct ipx_rt_def route;
	int		cursor;
	int		available_length;

	static char	*rip_type[3] = { "Request", "Response", "Unknown" };

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPX RIP");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	operation = tvb_get_ntohs(tvb, 0) - 1;

	if (check_col(pinfo->cinfo, COL_INFO)) {
		/* rip_types 0 and 1 are valid, anything else becomes 2 or "Unknown" */
		col_set_str(pinfo->cinfo, COL_INFO, rip_type[MIN(operation, 2)]);
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_ipxrip, tvb, 0, -1, FALSE);
		rip_tree = proto_item_add_subtree(ti, ett_ipxrip);

		if (operation < 2) {
			proto_tree_add_text(rip_tree, tvb, 0, 2,
			"RIP packet type: %s", rip_type[operation]);

			if (operation == 0) {
			  proto_tree_add_boolean_hidden(rip_tree, 
						     hf_ipxrip_request, 
						     tvb, 0, 2, 1);
			} else {
			  proto_tree_add_boolean_hidden(rip_tree, 
						     hf_ipxrip_response, 
						     tvb, 0, 2, 1);
			}

		}
		else {
			proto_tree_add_text(rip_tree, tvb, 0, 2, "Unknown RIP packet type");
		}

		available_length = tvb_reported_length(tvb);
		for (cursor =  2; cursor < available_length; cursor += 8) {
			tvb_memcpy(tvb, (guint8 *)&route.network, cursor, 4);
			route.hops = tvb_get_ntohs(tvb, cursor+4);
			route.ticks = tvb_get_ntohs(tvb, cursor+6);

			if (operation == IPX_RIP_REQUEST - 1) {
				proto_tree_add_text(rip_tree, tvb, cursor,      8,
					"Route Vector: %s, %d hop%s, %d tick%s",
					ipxnet_to_string((guint8*)&route.network),
					route.hops,  route.hops  == 1 ? "" : "s",
					route.ticks, route.ticks == 1 ? "" : "s");
			}
			else {
				proto_tree_add_text(rip_tree, tvb, cursor,      8,
					"Route Vector: %s, %d hop%s, %d tick%s (%d ms)",
					ipxnet_to_string((guint8*)&route.network),
					route.hops,  route.hops  == 1 ? "" : "s",
					route.ticks, route.ticks == 1 ? "" : "s",
					route.ticks * 1000 / 18);
			}
		}
	}
}



/* ================================================================= */
/* SAP	        							 */
/* ================================================================= */
static const char*
server_type(guint16 type)
{
	const char *p;

	/*
	 * Some of these are from ncpfs, others are from the book,
	 * others are from the page at
	 *
	 *	http://www.iana.org/assignments/novell-sap-numbers
	 *
	 * and some from the page at
	 *
	 *	http://www.rware.demon.co.uk/ipxsap.htm
	 *
	 * (see also the page at
	 *
	 *	http://developer.novell.com/research/appnotes/1998/february/03/06.htm
	 *
	 * which has a huge list - but many of the entries list only the
	 * organization owning the SAP type, not what the type is for).
	 */
	static const value_string server_vals[] = {
		{ 0x0000,	"Unknown" },
		{ 0x0001,	"User" },
		{ 0x0002,	"User Group" },
		{ 0x0003,	"Print Queue or Print Group" },
		{ 0x0004,	"File Server (SLIST source)" },
		{ 0x0005,	"Job Server" },
		{ 0x0006,	"Gateway" },
		{ 0x0007,	"Print Server or Silent Print Server" },
		{ 0x0008,	"Archive Queue" },
		{ 0x0009,	"Archive Server" },
		{ 0x000a,	"Job Queue" },
		{ 0x000b,	"Administration" },
		{ 0x000F,	"Novell TI-RPC" },
		{ 0x0017,	"Diagnostics" },
		{ 0x0020,	"NetBIOS" },
		{ 0x0021,	"NAS SNA Gateway" },
		{ 0x0023,	"NACS Async Gateway or Asynchronous Gateway" },
		{ 0x0024,	"Remote Bridge or Routing Service" },
		{ 0x0026,	"Bridge Server or Asynchronous Bridge Server" },
		{ 0x0027,	"TCP/IP Gateway Server" },
		{ 0x0028,	"Point to Point (Eicon) X.25 Bridge Server" },
		{ 0x0029,	"Eicon 3270 Gateway" },
		{ 0x002a,	"CHI Corp" },
		{ 0x002c,	"PC Chalkboard" },
		{ 0x002d,	"Time Synchronization Server or Asynchronous Timer" },
		{ 0x002e,	"ARCserve 5.0 / Palindrome Backup Director 4.x (PDB4)" },
		{ 0x0045,	"DI3270 Gateway" },
		{ 0x0047,	"Advertising Print Server" },
		{ 0x004a,	"NetBlazer Modems" },
		{ 0x004b,	"Btrieve VAP/NLM 5.0" },
		{ 0x004c,	"Netware SQL VAP/NLM Server" },
		{ 0x004d,	"Xtree Network Version/Netware XTree" },
		{ 0x0050,	"Btrieve VAP 4.11" },
		{ 0x0052,	"QuickLink (Cubix)" },
		{ 0x0053,	"Print Queue User" },
		{ 0x0058,	"Multipoint X.25 Eicon Router" },
		{ 0x0060,	"STLB/NLM" },
		{ 0x0064,	"ARCserve" },
		{ 0x0066,	"ARCserve 3.0" },
		{ 0x0072,	"WAN Copy Utility" },
		{ 0x007a,	"TES-Netware for VMS" },
		{ 0x0092,	"WATCOM Debugger or Emerald Tape Backup Server" },
		{ 0x0095,	"DDA OBGYN" },
		{ 0x0098,	"Netware Access Server (Asynchronous gateway)" },
		{ 0x009a,	"Netware for VMS II or Named Pipe Server" },
		{ 0x009b,	"Netware Access Server" },
		{ 0x009e,	"Portable Netware Server or SunLink NVT" },
		{ 0x00a1,	"Powerchute APC UPS NLM" },
		{ 0x00aa,	"LAWserve" },
		{ 0x00ac,	"Compaq IDA Status Monitor" },
		{ 0x0100,	"PIPE STAIL" },
		{ 0x0102,	"LAN Protect Bindery" },
		{ 0x0103,	"Oracle DataBase Server" },
		{ 0x0107,	"Netware 386 or RSPX Remote Console" },
		{ 0x010f,	"Novell SNA Gateway" },
		{ 0x0111,	"Test Server" },
		{ 0x0112,	"Print Server (HP)" },
		{ 0x0114,	"CSA MUX (f/Communications Executive)" },
		{ 0x0115,	"CSA LCA (f/Communications Executive)" },
		{ 0x0116,	"CSA CM (f/Communications Executive)" },
		{ 0x0117,	"CSA SMA (f/Communications Executive)" },
		{ 0x0118,	"CSA DBA (f/Communications Executive)" },
		{ 0x0119,	"CSA NMA (f/Communications Executive)" },
		{ 0x011a,	"CSA SSA (f/Communications Executive)" },
		{ 0x011b,	"CSA STATUS (f/Communications Executive)" },
		{ 0x011e,	"CSA APPC (f/Communications Executive)" },
		{ 0x0126,	"SNA TEST SSA Profile" },
		{ 0x012a,	"CSA TRACE (f/Communications Executive)" },
		{ 0x012b,	"Netware for SAA" },
		{ 0x012e,	"IKARUS virus scan utility" },
		{ 0x0130,	"Communications Executive" },
		{ 0x0133,	"NNS Domain Server or Netware Naming Services Domain" },
		{ 0x0135,	"Netware Naming Services Profile" },
		{ 0x0137,	"Netware 386 Print Queue or NNS Print Queue" },
		{ 0x0141,	"LAN Spool Server (Vap, Intel)" },
		{ 0x0152,	"IRMALAN Gateway" },
		{ 0x0154,	"Named Pipe Server" },
		{ 0x0166,	"NetWare Management" },
		{ 0x0168,	"Intel PICKIT Comm Server or Intel CAS Talk Server" },
		{ 0x0173,	"Compaq" },
		{ 0x0174,	"Compaq SNMP Agent" },
		{ 0x0175,	"Compaq" },
		{ 0x0180,	"XTree Server or XTree Tools" },
		{ 0x018A,	"NASI services broadcast server (Novell)" },
		{ 0x01b0,	"GARP Gateway (net research)" },
		{ 0x01b1,	"Binfview (Lan Support Group)" },
		{ 0x01bf,	"Intel LanDesk Manager" },
		{ 0x01ca,	"AXTEC" },
		{ 0x01cb,	"Shiva NetModem/E" },
		{ 0x01cc,	"Shiva LanRover/E" },
		{ 0x01cd,	"Shiva LanRover/T" },
		{ 0x01ce,	"Shiva Universal" },
		{ 0x01d8,	"Castelle FAXPress Server" },
		{ 0x01da,	"Castelle LANPress Print Server" },
		{ 0x01dc,	"Castelle FAX/Xerox 7033 Fax Server/Excel Lan Fax" },
		{ 0x01f0,	"LEGATO" },
		{ 0x01f5,	"LEGATO" },
		{ 0x0233,	"NMS Agent or Netware Management Agent" },
		{ 0x0237,	"NMS IPX Discovery or LANtern Read/Write Channel" },
		{ 0x0238,	"NMS IP Discovery or LANtern Trap/Alarm Channel" },
		{ 0x023a,	"LANtern" },
		{ 0x023c,	"MAVERICK" },
		{ 0x023f,	"SMS Testing and Development" },
		{ 0x024e,	"Netware Connect" },
		{ 0x024f,	"NASI server broadcast (Cisco)" },
		{ 0x026a,	"Network Management (NMS) Service Console" },
		{ 0x026b,	"Time Synchronization Server (Netware 4.x)" },
		{ 0x0278,	"Directory Server (Netware 4.x)" },
		{ 0x027b,	"Netware Management Agent" },
		{ 0x0280,	"Novell File and Printer Sharing Service for PC" },
		{ 0x0304,	"Novell SAA Gateway" },
		{ 0x0308,	"COM or VERMED 1" },
		{ 0x030a,	"Galacticomm's Worldgroup Server" },
		{ 0x030c,	"Intel Netport 2 or HP JetDirect or HP Quicksilver" },
		{ 0x0320,	"Attachmate Gateway" },
		{ 0x0327,	"Microsoft Diagnostics" },
		{ 0x0328,	"WATCOM SQL server" },
		{ 0x0335,	"MultiTech Systems Multisynch Comm Server" },
		{ 0x0343,	"Xylogics Remote Access Server or LAN Modem" },
		{ 0x0355,	"Arcada Backup Exec" },
		{ 0x0358,	"MSLCD1" },
		{ 0x0361,	"NETINELO" },
		{ 0x037e,	"Powerchute UPS Monitoring" },
		{ 0x037f,	"ViruSafe Notify" },
		{ 0x0386,	"HP Bridge" },
		{ 0x0387,	"HP Hub" },
		{ 0x0394,	"NetWare SAA Gateway" },
		{ 0x039b,	"Lotus Notes" },
		{ 0x03b7,	"Certus Anti Virus NLM" },
		{ 0x03c4,	"ARCserve 4.0 (Cheyenne)" },
		{ 0x03c7,	"LANspool 3.5 (Intel)" },
		{ 0x03d7,	"Lexmark printer server (type 4033-011)" },
		{ 0x03d8,	"Lexmark XLE printer server (type 4033-301)" },
		{ 0x03dd,	"Banyan ENS for Netware Client NLM" },
		{ 0x03de,	"Gupta Sequel Base Server or NetWare SQL" },
		{ 0x03e1,	"Univel Unixware" },
		{ 0x03e4,	"Univel Unixware" },
		{ 0x03fc,	"Intel Netport" },
		{ 0x03fd,	"Intel Print Server Queue" },
		{ 0x040A,	"ipnServer" },
		{ 0x040D,	"LVERRMAN" },
		{ 0x040E,	"LVLIC" },
		{ 0x0414,	"NET Silicon (DPI)/Kyocera" },
		{ 0x0429,	"Site Lock Virus (Brightworks)" },
		{ 0x0432,	"UFHELP R" },
		{ 0x0433,	"Synoptics 281x Advanced SNMP Agent" },
		{ 0x0444,	"Microsoft NT SNA Server" },
		{ 0x0448,	"Oracle" },
		{ 0x044c,	"ARCserve 5.01" },
		{ 0x0457,	"Canon GP55 Running on a Canon GP55 network printer" },
		{ 0x045a,	"QMS Printers" },
		{ 0x045b,	"Dell SCSI Array (DSA) Monitor" },
		{ 0x0491,	"NetBlazer Modems" },
		{ 0x04ac,	"On-Time Scheduler NLM" },
		{ 0x04b0,	"CD-Net (Meridian)" },
		{ 0x0513,	"Emulex NQA" },
		{ 0x0520,	"Site Lock Checks" },
		{ 0x0529,	"Site Lock Checks (Brightworks)" },
		{ 0x052d,	"Citrix OS/2 App Server" },
		{ 0x0535,	"Tektronix" },
		{ 0x0536,	"Milan" },
		{ 0x055d,	"Attachmate SNA gateway" },
		{ 0x056b,	"IBM 8235 modem server" },
		{ 0x056c,	"Shiva LanRover/E PLUS" },
		{ 0x056d,	"Shiva LanRover/T PLUS" },
		{ 0x0580,	"McAfee's NetShield anti-virus" },
		{ 0x05B8,	"NLM to workstation communication (Revelation Software)" },
		{ 0x05BA,	"Compatible Systems Routers" },
		{ 0x05BE,	"Cheyenne Hierarchical Storage Manager" },
		{ 0x0606,	"JCWatermark Imaging" },
		{ 0x060c,	"AXIS Network Printer" },
		{ 0x0610,	"Adaptec SCSI Management" },
		{ 0x0621,	"IBM AntiVirus NLM" },
		{ 0x0640,	"Microsoft Gateway Services for NetWare" },
/*		{ 0x0640,	"NT Server-RPC/GW for NW/Win95 User Level Sec" }, */
		{ 0x064e,	"Microsoft Internet Information Server" },
		{ 0x067b,	"Microsoft Win95/98 File and Print Sharing for NetWare" },
		{ 0x067c,	"Microsoft Win95/98 File and Print Sharing for NetWare" },
		{ 0x076C,	"Xerox" },
		{ 0x079b,	"Shiva LanRover/E 115" },
		{ 0x079c,	"Shiva LanRover/T 115" },
		{ 0x07B4,	"Cubix WorldDesk" },
		{ 0x07c2,	"Quarterdeck IWare Connect V2.x NLM" },
		{ 0x07c1,	"Quarterdeck IWare Connect V3.x NLM" },
		{ 0x0810,	"ELAN License Server Demo" },
		{ 0x0824,	"Shiva LanRover Access Switch/E" },
		{ 0x086a,	"ISSC collector NLMs" },
		{ 0x087f,	"ISSC DAS agent for AIX" },
		{ 0x0880,	"Intel Netport PRO" },
		{ 0x0881,	"Intel Netport PRO" },
		{ 0x0b29,	"Site Lock" },
		{ 0x0c29,	"Site Lock Applications" },
		{ 0x0c2c,	"Licensing Server" },
		{ 0x2101,	"Performance Technology Instant Internet" },
		{ 0x2380,	"LAI Site Lock" },
		{ 0x238c,	"Meeting Maker" },
		{ 0x4808,	"Site Lock Server or Site Lock Metering VAP/NLM" },
		{ 0x5555,	"Site Lock User" },
		{ 0x6312,	"Tapeware" },
		{ 0x6f00,	"Rabbit Gateway (3270)" },
		{ 0x7703,	"MODEM" },
		{ 0x8002,	"NetPort Printers (Intel) or LANport" },
		{ 0x8008,	"WordPerfect Network Version" },
		{ 0x85BE,	"Cisco Enhanced Interior Routing Protocol (EIGRP)" },
		{ 0x8888,	"WordPerfect Network Version or Quick Network Management" },
		{ 0x9000,	"McAfee's NetShield anti-virus" },
		{ 0x9604,	"CSA-NT_MON" },
		{ 0xb6a8,	"Ocean Isle Reachout Remote Control" },
		{ 0xf11f,	"Site Lock Metering VAP/NLM" },
		{ 0xf1ff,	"Site Lock" },
		{ 0xf503,	"Microsoft SQL Server" },
		{ 0xf905,	"IBM Time and Place/2 application" },
		{ 0xfbfb,	"TopCall III fax server" },
		{ 0xffff,	"Any Service or Wildcard" },
		{ 0x0000,	NULL }
	};

	p = match_strval(type, server_vals);
	if (p) {
		return p;
	}
	else {
		return "Unknown";
	}
}

static void
dissect_ipxsap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*sap_tree, *s_tree;
	proto_item	*ti;
	int		cursor;
	struct sap_query query;
	struct sap_server_ident server;

	static char	*sap_type[4] = { "General Query", "General Response",
		"Nearest Query", "Nearest Response" };

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPX SAP");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	query.query_type = tvb_get_ntohs(tvb, 0);
	query.server_type = tvb_get_ntohs(tvb, 2);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		if (query.query_type >= 1 && query.query_type <= 4) {
			col_set_str(pinfo->cinfo, COL_INFO, sap_type[query.query_type - 1]);
		}
		else {
			col_set_str(pinfo->cinfo, COL_INFO, "Unknown Packet Type");
		}
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_sap, tvb, 0, -1, FALSE);
		sap_tree = proto_item_add_subtree(ti, ett_ipxsap);

		if (query.query_type >= 1 && query.query_type <= 4) {
			proto_tree_add_text(sap_tree, tvb, 0, 2, sap_type[query.query_type - 1]);
			if ((query.query_type - 1) % 2) {
			  proto_tree_add_boolean_hidden(sap_tree, 
						     hf_sap_response, 
						     tvb, 0, 2, 1);
			} else {
			  proto_tree_add_boolean_hidden(sap_tree, 
						     hf_sap_request, 
						     tvb, 0, 2, 1);
			}
		}
		else {
			proto_tree_add_text(sap_tree, tvb, 0, 2,
					"Unknown SAP Packet Type %d", query.query_type);
		}

		if (query.query_type == IPX_SAP_GENERAL_RESPONSE ||
				query.query_type == IPX_SAP_NEAREST_RESPONSE) { /* responses */

			int available_length = tvb_reported_length(tvb);
			for (cursor =  2; (cursor + 64) <= available_length; cursor += 64) {
				server.server_type = tvb_get_ntohs(tvb, cursor);
				tvb_memcpy(tvb, (guint8 *)server.server_name,
				    cursor+2, 48);
				tvb_memcpy(tvb, (guint8 *)&server.server_network,
				    cursor+50, 4);
				tvb_memcpy(tvb, (guint8 *)&server.server_node,
				    cursor+54, 6);
				server.server_port = tvb_get_ntohs(tvb, cursor+60);
				server.intermediate_network = tvb_get_ntohs(tvb, cursor+62);

				ti = proto_tree_add_text(sap_tree, tvb, cursor+2, 48,
					"Server Name: %s", server.server_name);
				s_tree = proto_item_add_subtree(ti, ett_ipxsap_server);

				proto_tree_add_text(s_tree, tvb, cursor, 2, "Server Type: %s (0x%04X)",
						server_type(server.server_type), server.server_type);
				proto_tree_add_text(s_tree, tvb, cursor+50, 4, "Network: %s",
						ipxnet_to_string((guint8*)tvb_get_ptr(tvb, cursor+50, 4)));
				proto_tree_add_text(s_tree, tvb, cursor+54, 6, "Node: %s",
						ether_to_str((guint8*)tvb_get_ptr(tvb, cursor+54, 6)));
				proto_tree_add_text(s_tree, tvb, cursor+60, 2, "Socket: %s (0x%04x)",
						socket_text(server.server_port), server.server_port);
				proto_tree_add_text(s_tree, tvb, cursor+62, 2,
						"Intermediate Networks: %d",
						server.intermediate_network);
			}
		}
		else {  /* queries */
			proto_tree_add_text(sap_tree, tvb, 2, 2, "Server Type: %s (0x%04X)",
					server_type(query.server_type), query.server_type);
		}
	}
}

void
proto_register_ipx(void)
{
	static hf_register_info hf_ipx[] = {
		{ &hf_ipx_checksum,
		{ "Checksum",		"ipx.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
			"", HFILL }},

		{ &hf_ipx_len,
		{ "Length",		"ipx.len", FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_ipx_hops,
		{ "Transport Control (Hops)", "ipx.hops", FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_ipx_packet_type,
		{ "Packet Type",	"ipx.packet_type", FT_UINT8, BASE_HEX, VALS(ipx_packet_type_vals),
			0x0,
			"", HFILL }},

		{ &hf_ipx_dnet,
		{ "Destination Network","ipx.dst.net", FT_IPXNET, BASE_NONE, NULL, 0x0,
			"", HFILL }},

		{ &hf_ipx_dnode,
		{ "Destination Node",	"ipx.dst.node", FT_ETHER, BASE_NONE, NULL, 0x0,
			"", HFILL }},

		{ &hf_ipx_dsocket,
		{ "Destination Socket",	"ipx.dst.socket", FT_UINT16, BASE_HEX,
			VALS(ipx_socket_vals), 0x0,
			"", HFILL }},

		{ &hf_ipx_snet,
		{ "Source Network","ipx.src.net", FT_IPXNET, BASE_NONE, NULL, 0x0,
			"", HFILL }},

		{ &hf_ipx_snode,
		{ "Source Node",	"ipx.src.node", FT_ETHER, BASE_NONE, NULL, 0x0,
			"", HFILL }},

		{ &hf_ipx_ssocket,
		{ "Source Socket",	"ipx.src.socket", FT_UINT16, BASE_HEX,
			VALS(ipx_socket_vals), 0x0,
			"", HFILL }},
	};

	static hf_register_info hf_spx[] = {
		{ &hf_spx_connection_control,
		{ "Connection Control",		"spx.ctl", 
		  FT_UINT8,	BASE_HEX,	NULL,	0x0,
		  "", HFILL }},

		{ &hf_spx_datastream_type,
		{ "Datastream type",	       	"spx.type", 
		  FT_UINT8,	BASE_HEX,	NULL,	0x0,
		  "", HFILL }},

		{ &hf_spx_src_id,
		{ "Source Connection ID",	"spx.src", 
		  FT_UINT16,	BASE_DEC,	NULL,	0x0,
		  "", HFILL }},

		{ &hf_spx_dst_id,
		{ "Destination Connection ID",	"spx.dst", 
		  FT_UINT16,	BASE_DEC,	NULL,	0x0,
		  "", HFILL }},

		{ &hf_spx_seq_nr,
		{ "Sequence Number",		"spx.seq", 
		  FT_UINT16,	BASE_DEC,	NULL,	0x0,
		  "", HFILL }},

		{ &hf_spx_ack_nr,
		{ "Acknowledgment Number",	"spx.ack", 
		  FT_UINT16,	BASE_DEC,	NULL,	0x0,
		  "", HFILL }},

		{ &hf_spx_all_nr,
		{ "Allocation Number",		"spx.alloc", 
		  FT_UINT16,	BASE_DEC,	NULL,	0x0,
		  "", HFILL }}
	};

	static hf_register_info hf_ipxrip[] = {
		{ &hf_ipxrip_request,
		{ "Request",			"ipxrip.request", 
		  FT_BOOLEAN,	BASE_NONE,	NULL,	0x0,
		  "TRUE if IPX RIP request", HFILL }},

		{ &hf_ipxrip_response,
		{ "Response",			"ipxrip.response", 
		  FT_BOOLEAN,	BASE_NONE,	NULL,	0x0,
		  "TRUE if IPX RIP response", HFILL }}
	};

	static hf_register_info hf_sap[] = {
		{ &hf_sap_request,
		{ "Request",			"ipxsap.request", 
		  FT_BOOLEAN,	BASE_NONE,	NULL,	0x0,
		  "TRUE if SAP request", HFILL }},

		{ &hf_sap_response,
		{ "Response",			"ipxsap.response", 
		  FT_BOOLEAN,	BASE_NONE,	NULL,	0x0,
		  "TRUE if SAP response", HFILL }}
	};

	static hf_register_info hf_ipxmsg[] = {
		{ &hf_msg_conn,
		{ "Connection Number",			"ipxmsg.conn", 
		  FT_UINT8,	BASE_DEC,	NULL,	0x0,
		  "Connection Number", HFILL }},

		{ &hf_msg_sigchar,
		{ "Signature Char",			"ipxmsg.sigchar", 
		  FT_UINT8,	BASE_DEC,	VALS(ipxmsg_sigchar_vals),	0x0,
		  "Signature Char", HFILL }}
	};

	static gint *ett[] = {
		&ett_ipx,
		&ett_spx,
		&ett_ipxmsg,
		&ett_ipxrip,
		&ett_ipxsap,
		&ett_ipxsap_server,
	};

	proto_ipx = proto_register_protocol("Internetwork Packet eXchange",
	    "IPX", "ipx");
	proto_register_field_array(proto_ipx, hf_ipx, array_length(hf_ipx));

	register_dissector("ipx", dissect_ipx, proto_ipx);

	proto_spx = proto_register_protocol("Sequenced Packet eXchange",
	    "SPX", "spx");
	proto_register_field_array(proto_spx, hf_spx, array_length(hf_spx));

	proto_ipxrip = proto_register_protocol("IPX Routing Information Protocol",
	    "IPX RIP", "ipxrip");
	proto_register_field_array(proto_ipxrip, hf_ipxrip, array_length(hf_ipxrip));

	proto_ipxmsg = proto_register_protocol("IPX Message", "IPX MSG",
	    "ipxmsg");
	proto_register_field_array(proto_ipxmsg, hf_ipxmsg, array_length(hf_ipxmsg));

	proto_sap = proto_register_protocol("Service Advertisement Protocol",
	    "IPX SAP", "ipxsap");
	register_dissector("ipxsap", dissect_ipxsap, proto_sap);

	proto_register_field_array(proto_sap, hf_sap, array_length(hf_sap));

	proto_register_subtree_array(ett, array_length(ett));

	ipx_type_dissector_table = register_dissector_table("ipx.packet_type",
	    "IPX packet type", FT_UINT8, BASE_HEX);
	ipx_socket_dissector_table = register_dissector_table("ipx.socket",
	    "IPX socket", FT_UINT16, BASE_HEX);
}

void
proto_reg_handoff_ipx(void)
{
	dissector_handle_t ipx_handle, spx_handle;
	dissector_handle_t ipxsap_handle, ipxrip_handle;
	dissector_handle_t ipxmsg_handle;

	ipx_handle = find_dissector("ipx");
	dissector_add("udp.port", UDP_PORT_IPX, ipx_handle);
	dissector_add("ethertype", ETHERTYPE_IPX, ipx_handle);
	dissector_add("chdlctype", ETHERTYPE_IPX, ipx_handle);
	dissector_add("ppp.protocol", PPP_IPX, ipx_handle);
	dissector_add("llc.dsap", SAP_NETWARE, ipx_handle);
	dissector_add("null.type", BSD_AF_IPX, ipx_handle);
	dissector_add("gre.proto", ETHERTYPE_IPX, ipx_handle);
	spx_handle = create_dissector_handle(dissect_spx, proto_spx);
	dissector_add("ipx.packet_type", IPX_PACKET_TYPE_SPX, spx_handle);
	ipxsap_handle = find_dissector("ipxsap");
	dissector_add("ipx.socket", IPX_SOCKET_SAP, ipxsap_handle);
	ipxrip_handle = create_dissector_handle(dissect_ipxrip, proto_ipxrip);
	dissector_add("ipx.socket", IPX_SOCKET_IPXRIP, ipxrip_handle);
	ipxmsg_handle = create_dissector_handle(dissect_ipxmsg, proto_ipxmsg);
	dissector_add("ipx.socket", IPX_SOCKET_IPX_MESSAGE, ipxmsg_handle);
	data_handle = find_dissector("data");
}
