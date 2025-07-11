/* packet-ntp.c
 * Routines for NTP packet dissection
 * Copyright 1999, Nathan Neulinger <nneul@umr.edu>
 *
 * $Id: packet-ntp.c,v 1.34 2002/01/24 09:20:50 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
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

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <time.h>
#include <math.h>
#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>
#include <epan/resolv.h>
#include "packet-ntp.h"

/*
 * Dissecting NTP packets version 3 and 4 (RFC2030, RFC1769, RFC1361,
 * RFC1305).
 *
 * Those packets have simple structure:
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |LI | VN  |Mode |    Stratum    |     Poll      |   Precision   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          Root Delay                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Root Dispersion                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Reference Identifier                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                   Reference Timestamp (64)                    |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                   Originate Timestamp (64)                    |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Receive Timestamp (64)                     |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Transmit Timestamp (64)                    |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Key Identifier (optional) (32)                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Message Digest (optional) (128)               |
 * |                                                               |
 * |                                                               |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * NTP timestamps are represented as a 64-bit unsigned fixed-point number,
 * in seconds relative to 0h on 1 January 1900. The integer part is in the
 * first 32 bits and the fraction part in the last 32 bits.
 */

#define UDP_PORT_NTP	123
#define TCP_PORT_NTP	123

/* Leap indicator, 2bit field is used to warn of a inserted/deleted
 * second, or to alarm loosed synchronization.
 */
#define NTP_LI_MASK	0xC0

#define NTP_LI_NONE	0
#define NTP_LI_61	1
#define NTP_LI_59	2
#define NTP_LI_ALARM	3

static const value_string li_types[] = {
	{ NTP_LI_NONE,	"no warning" },
	{ NTP_LI_61,	"last minute has 61 seconds" },
	{ NTP_LI_59,	"last minute has 59 seconds" },
	{ NTP_LI_ALARM,	"alarm condition (clock not synchronized)" },
	{ 0,		NULL}
};

/* Version info, 3bit field informs about NTP version used in particular
 * packet. According to rfc2030, version info could be only 3 or 4, but I
 * have noticed packets with 1 or even 6 as version numbers. They are
 * produced as a result of ntptrace command. Are those packets mailformed
 * on purpose? I don't know yet, probably some browsing through ntp sources
 * would help. My solution is to put them as reserved for now.
 */
#define NTP_VN_MASK	0x38

static const value_string ver_nums[] = {
	{ 0,	"reserved" },
	{ 1,	"reserved" },
	{ 2,	"reserved" },
	{ 3,	"NTP Version 3" },
	{ 4,	"NTP Version 4" },
	{ 5,	"reserved" },
	{ 6,	"reserved" },
	{ 7,	"reserved" },
	{ 0,	NULL}
};

/* Mode, 3bit field representing mode of comunication.
 */
#define NTP_MODE_MASK   7

#define NTP_MODE_RSV	0
#define NTP_MODE_SYMACT	1
#define NTP_MODE_SYMPAS	2
#define NTP_MODE_CLIENT	3
#define NTP_MODE_SERVER	4
#define NTP_MODE_BCAST	5
#define NTP_MODE_CTRL	6
#define NTP_MODE_PRIV	7

static const value_string mode_types[] = {
	{ NTP_MODE_RSV,		"reserved" },
	{ NTP_MODE_SYMACT,	"symmetric active" },
	{ NTP_MODE_SYMPAS,	"symmetric passive" },
	{ NTP_MODE_CLIENT,	"client" },
	{ NTP_MODE_SERVER,	"server" },
	{ NTP_MODE_BCAST,	"broadcast" },
	{ NTP_MODE_CTRL,	"reserved for NTP control message"},
	{ NTP_MODE_PRIV,	"reserved for private use" },
	{ 0,		NULL}
};

/* According to rfc, primary (stratum-0 and stratum-1) servers should set
 * their Reference Clock ID (4bytes field) according to following table:
 */
static const struct {
	char *id;
	char *data;
} primary_sources[] = {
	{ "LOCL",	"uncalibrated local clock" },
	{ "PPS\0",	"atomic clock or other pulse-per-second source" },
	{ "ACTS",	"NIST dialup modem service" },
	{ "USNO",	"USNO modem service" },
	{ "PTB\0",	"PTB (Germany) modem service" },
	{ "TDF\0",	"Allouis (France) Radio 164 kHz" },
	{ "DCF\0",	"Mainflingen (Germany) Radio 77.5 kHz" },
	{ "MSF\0",	"Rugby (UK) Radio 60 kHz" },
	{ "WWV\0",	"Ft. Collins (US) Radio 2.5, 5, 10, 15, 20 MHz" },
	{ "WWVB",	"Boulder (US) Radio 60 kHz" },
	{ "WWVH",	"Kaui Hawaii (US) Radio 2.5, 5, 10, 15 MHz" },
	{ "CHU\0",	"Ottawa (Canada) Radio 3330, 7335, 14670 kHz" },
	{ "LORC",	"LORAN-C radionavigation system" },
	{ "OMEG",	"OMEGA radionavigation system" },
	{ "GPS\0",	"Global Positioning Service" },
	{ "GOES",	"Geostationary Orbit Environment Satellite" },
	{ "DCN\0",	"DCN routing protocol" },
	{ "NIST",	"NIST public modem" },
	{ "TSP\0",	"TSP time protocol" },
	{ "DTS\0",	"Digital Time Service" },
	{ "ATOM",	"Atomic clock (calibrated)" },
	{ "VLF\0",	"VLF radio (OMEGA,, etc.)" },
	{ "IRIG",	"IRIG-B timecode" },
	{ "1PPS",	"External 1 PPS input" },
	{ "FREE",	"(Internal clock)" },
	{ NULL,		NULL}
};

static int proto_ntp = -1;
static int hf_ntp_flags = -1;
static int hf_ntp_flags_li = -1;
static int hf_ntp_flags_vn = -1;
static int hf_ntp_flags_mode = -1;
static int hf_ntp_stratum = -1;
static int hf_ntp_ppoll = -1;
static int hf_ntp_precision = -1;
static int hf_ntp_rootdelay = -1;
static int hf_ntp_rootdispersion = -1;
static int hf_ntp_refid = -1;
static int hf_ntp_reftime = -1;
static int hf_ntp_org = -1;
static int hf_ntp_rec = -1;
static int hf_ntp_xmt = -1;
static int hf_ntp_keyid = -1;
static int hf_ntp_mac = -1;

static gint ett_ntp = -1;
static gint ett_ntp_flags = -1;

/* ntp_fmt_ts - converts NTP timestamp to human readable string.
 * reftime - 64bit timestamp (IN)
 * buff - string buffer for result (OUT)
 * returns pointer to filled buffer.
 */
static char *
ntp_fmt_ts(const guint8 *reftime, char* buff)
{
	guint32 tempstmp, tempfrac;
	time_t temptime;
	struct tm *bd;
	double fractime;

	tempstmp = pntohl(&reftime[0]);
	tempfrac = pntohl(&reftime[4]);
	if ((tempstmp == 0) && (tempfrac == 0)) {
		strcpy (buff, "NULL");
		return buff;
	} else {
		temptime = tempstmp - (guint32) NTP_BASETIME;
		bd = gmtime(&temptime);
		if (bd != NULL) {
			fractime = bd->tm_sec + tempfrac / 4294967296.0;
			snprintf(buff, NTP_TS_SIZE,
				 "%04d-%02d-%02d %02d:%02d:%07.4f UTC",
				 bd->tm_year + 1900, bd->tm_mon + 1, bd->tm_mday,
				 bd->tm_hour, bd->tm_min, fractime);
		} else
			strncpy(buff, "Not representable", NTP_TS_SIZE);
	}
	return buff;
}
		
/* dissect_ntp - dissects NTP packet data
 * tvb - tvbuff for packet data (IN)
 * pinfo - packet info
 * proto_tree - resolved protocol tree
 */
static void
dissect_ntp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree      *ntp_tree, *flags_tree;
	proto_item	*ti, *tf;
	guint8		flags;
	guint8		stratum;
	guint8		ppoll;
	gint8		precision;
	double		rootdelay;
	double		rootdispersion;
	const guint8	*refid;
	const guint8	*reftime;
	const guint8	*org;
	const guint8	*rec;
	const guint8	*xmt;
	gchar		buff[NTP_TS_SIZE];
	int		i;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "NTP");

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "NTP");

	if (tree) {
		/* Adding NTP item and subtree */
		ti = proto_tree_add_item(tree, proto_ntp, tvb, 0, -1, FALSE);
		ntp_tree = proto_item_add_subtree(ti, ett_ntp);

		flags = tvb_get_guint8(tvb, 0);
		tf = proto_tree_add_uint(ntp_tree, hf_ntp_flags, tvb, 0, 1,
		    flags);

		/* Adding flag subtree and items */
		flags_tree = proto_item_add_subtree(tf, ett_ntp_flags);
		proto_tree_add_uint(flags_tree, hf_ntp_flags_li, tvb, 0, 1,
					   flags);
		proto_tree_add_uint(flags_tree, hf_ntp_flags_vn, tvb, 0, 1,
					   flags);
		proto_tree_add_uint(flags_tree, hf_ntp_flags_mode, tvb, 0, 1,
					   flags);

		/* Stratum, 1byte field represents distance from primary source
		 */
		stratum = tvb_get_guint8(tvb, 1);
		if (stratum == 0) {
			strcpy (buff, "Peer Clock Stratum: unspecified or unavailable (%u)");
		} else if (stratum == 1) {
			strcpy (buff, "Peer Clock Stratum: primary reference (%u)");
		} else if ((stratum >= 2) && (stratum <= 15)) {
			strcpy (buff, "Peer Clock Stratum: secondary reference (%u)");
		} else {
			strcpy (buff, "Peer Clock Stratum: reserved: %u");
		}
		proto_tree_add_uint_format(ntp_tree, hf_ntp_stratum, tvb, 1, 1,
					   stratum, buff, stratum);
		/* Poll interval, 1byte field indicating the maximum interval
		 * between successive messages, in seconds to the nearest
		 * power of two.
		 */
		ppoll = tvb_get_guint8(tvb, 2);
		proto_tree_add_uint_format(ntp_tree, hf_ntp_ppoll, tvb, 2, 1,
					   ppoll,
					   (((ppoll >= 4) && (ppoll <= 16)) ? 
					   "Peer Polling Interval: %u (%u sec)" :
					   "Peer Polling Interval: invalid (%u)"),
					   ppoll,
					   1 << ppoll);

		/* Precision, 1byte field indicating the precision of the
		 * local clock, in seconds to the nearest power of two.
		 */
		precision = tvb_get_guint8(tvb, 3);
		proto_tree_add_uint_format(ntp_tree, hf_ntp_precision, tvb, 3, 1,
					   precision,
					   "Peer Clock Precision: %8.6f sec",
					   pow(2, precision));

		/* Root Delay is a 32-bit signed fixed-point number indicating
		 * the total roundtrip delay to the primary reference source,
		 * in seconds with fraction point between bits 15 and 16.
		 */
		rootdelay = ((gint16)tvb_get_ntohs(tvb, 4)) +
				(tvb_get_ntohs(tvb, 6) / 65536.0);
		proto_tree_add_double_format(ntp_tree, hf_ntp_rootdelay, tvb, 4, 4,
					   rootdelay,
					   "Root Delay: %9.4f sec",
					   rootdelay);

		/* Root Dispersion, 32-bit unsigned fixed-point number indicating
		 * the nominal error relative to the primary reference source, in
		 * seconds with fraction point between bits 15 and 16.
		 */
		rootdispersion = ((gint16)tvb_get_ntohs(tvb, 8)) +
					(tvb_get_ntohs(tvb, 10) / 65536.0);
		proto_tree_add_double_format(ntp_tree, hf_ntp_rootdispersion, tvb, 8, 4,
					   rootdispersion,
					   "Clock Dispersion: %9.4f sec",
					   rootdispersion);

		/* Now, there is a problem with secondary servers.  Standards
		 * asks from stratum-2 - stratum-15 servers to set this to the
		 * low order 32 bits of the latest transmit timestamp of the
		 * reference source.
		 * But, all V3 and V4 servers set this to IP adress of their
		 * higher level server. My decision was to resolve this address.
		 */
		refid = tvb_get_ptr(tvb, 12, 4);
		if (stratum <= 1) {
			snprintf (buff, sizeof buff,
			    "Unindentified reference source '%.4s'",
			    refid);
			for (i = 0; primary_sources[i].id; i++) {
				if (memcmp (refid, primary_sources[i].id,
				    4) == 0) {
					strcpy (buff, primary_sources[i].data);
					break;
				}
			}
		} else {
			buff[sizeof(buff) - 1] = '\0';
			strncpy (buff, get_hostname (htonl(tvb_get_ntohl(tvb, 12))),
			    sizeof(buff));
			if (buff[sizeof(buff) - 1] != '\0')
				strcpy(&buff[sizeof(buff) - 4], "...");
		}
		proto_tree_add_bytes_format(ntp_tree, hf_ntp_refid, tvb, 12, 4,
					   refid,
					   "Reference Clock ID: %s", buff);

		/* Reference Timestamp: This is the time at which the local clock was
		 * last set or corrected.
		 */
		reftime = tvb_get_ptr(tvb, 16, 8);
		proto_tree_add_bytes_format(ntp_tree, hf_ntp_reftime, tvb, 16, 8,
					   reftime,
				           "Reference Clock Update Time: %s", 
					   ntp_fmt_ts(reftime, buff));

		/* Originate Timestamp: This is the time at which the request departed
		 * the client for the server.
		 */
		org = tvb_get_ptr(tvb, 24, 8);
		proto_tree_add_bytes_format(ntp_tree, hf_ntp_org, tvb, 24, 8,
					   org,
				           "Originate Time Stamp: %s", 
					   ntp_fmt_ts(org, buff));
		/* Receive Timestamp: This is the time at which the request arrived at
		 * the server.
		 */
		rec = tvb_get_ptr(tvb, 32, 8);
		proto_tree_add_bytes_format(ntp_tree, hf_ntp_rec, tvb, 32, 8,
					   rec,
				           "Receive Time Stamp: %s", 
					   ntp_fmt_ts(rec, buff));
		/* Transmit Timestamp: This is the time at which the reply departed the
		 * server for the client.
		 */
		xmt = tvb_get_ptr(tvb, 40, 8);
		proto_tree_add_bytes_format(ntp_tree, hf_ntp_xmt, tvb, 40, 8,
					   xmt,
				           "Transmit Time Stamp: %s", 
					   ntp_fmt_ts(xmt, buff));

		/* When the NTP authentication scheme is implemented, the
		 * Key Identifier and Message Digest fields contain the
		 * message authentication code (MAC) information defined in
		 * Appendix C of RFC-1305. Will print this as hex code for now.
		 */
		if ( tvb_reported_length_remaining(tvb, 48) >= 4 )
			proto_tree_add_item(ntp_tree, hf_ntp_keyid, tvb, 48, 4,
					   FALSE);
		if ( tvb_reported_length_remaining(tvb, 52) > 0 )
			proto_tree_add_item(ntp_tree, hf_ntp_mac, tvb, 52,
					   tvb_reported_length_remaining(tvb, 52),
					   FALSE);

	}
}

void
proto_register_ntp(void)
{
	static hf_register_info hf[] = {
		{ &hf_ntp_flags, {	
			"Flags", "ntp.flags", FT_UINT8, BASE_HEX, 
			NULL, 0, "Flags (Leap/Version/Mode)", HFILL }},
		{ &hf_ntp_flags_li, {
			"Leap Indicator", "ntp.flags.li", FT_UINT8, BASE_DEC,
			VALS(li_types), NTP_LI_MASK, "Leap Indicator", HFILL }},
		{ &hf_ntp_flags_vn, {
			"Version number", "ntp.flags.vn", FT_UINT8, BASE_DEC,
			VALS(ver_nums), NTP_VN_MASK, "Version number", HFILL }},
		{ &hf_ntp_flags_mode, {
			"Mode", "ntp.flags.mode", FT_UINT8, BASE_DEC,
			VALS(mode_types), NTP_MODE_MASK, "Mode", HFILL }},
		{ &hf_ntp_stratum, {	
			"Peer Clock Stratum", "ntp.stratum", FT_UINT8, BASE_DEC,
			NULL, 0, "Peer Clock Stratum", HFILL }},
		{ &hf_ntp_ppoll, {	
			"Peer Polling Interval", "ntp.ppoll", FT_UINT8, BASE_DEC, 
			NULL, 0, "Peer Polling Interval", HFILL }},
		{ &hf_ntp_precision, {	
			"Peer Clock Precision", "ntp.precision", FT_UINT8, BASE_DEC, 
			NULL, 0, "Peer Clock Precision", HFILL }},
		{ &hf_ntp_rootdelay, {	
			"Root Delay", "ntp.rootdelay", FT_DOUBLE, BASE_DEC,
			NULL, 0, "Root Delay", HFILL }},
		{ &hf_ntp_rootdispersion, {	
			"Clock Dispersion", "ntp.rootdispersion", FT_DOUBLE, BASE_DEC, 
			NULL, 0, "Clock Dispersion", HFILL }},
		{ &hf_ntp_refid, {	
			"Reference Clock ID", "ntp.refid", FT_BYTES, BASE_NONE, 
			NULL, 0, "Reference Clock ID", HFILL }},
		{ &hf_ntp_reftime, {	
			"Reference Clock Update Time", "ntp.reftime", FT_BYTES, BASE_NONE, 
			NULL, 0, "Reference Clock Update Time", HFILL }},
		{ &hf_ntp_org, {	
			"Originate Time Stamp", "ntp.org", FT_BYTES, BASE_NONE, 
			NULL, 0, "Originate Time Stamp", HFILL }},
		{ &hf_ntp_rec, {	
			"Receive Time Stamp", "ntp.rec", FT_BYTES, BASE_NONE, 
			NULL, 0, "Receive Time Stamp", HFILL }},
		{ &hf_ntp_xmt, {	
			"Transmit Time Stamp", "ntp.xmt", FT_BYTES, BASE_NONE, 
			NULL, 0, "Transmit Time Stamp", HFILL }},
		{ &hf_ntp_keyid, {	
			"Key ID", "ntp.keyid", FT_BYTES, BASE_HEX, 
			NULL, 0, "Key ID", HFILL }},
		{ &hf_ntp_mac, {	
			"Message Authentication Code", "ntp.mac", FT_BYTES, BASE_HEX, 
			NULL, 0, "Message Authentication Code", HFILL }},
        };
	static gint *ett[] = {
		&ett_ntp,
		&ett_ntp_flags,
	};

	proto_ntp = proto_register_protocol("Network Time Protocol", "NTP",
	    "ntp");
	proto_register_field_array(proto_ntp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ntp(void)
{
	dissector_handle_t ntp_handle;

	ntp_handle = create_dissector_handle(dissect_ntp, proto_ntp);
	dissector_add("udp.port", UDP_PORT_NTP, ntp_handle);
	dissector_add("tcp.port", TCP_PORT_NTP, ntp_handle);
}
