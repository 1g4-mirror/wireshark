/* packet-quake.c
 * Routines for Time Synchronization Protocol (TSP) packet dissection
 *
 * Uwe Girlich <Uwe.Girlich@philosys.de>
 *
 * $Id: packet-tsp.c,v 1.1 2002/01/31 07:50:29 girlich Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-quake.c
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
# include <netinet/in.h>
#endif

#include <glib.h>
#include <epan/packet.h>

/* 
 * For a full documentation of the Time Synchronization Protocol (TSP) see:
 * http://docs.freebsd.org/44doc/smm/12.timed/paper.pdf
 */

static int proto_tsp = -1;
static int hf_tsp_type = -1; 
static int hf_tsp_vers = -1; 
static int hf_tsp_seq = -1; 
static int hf_tsp_hopcnt = -1; 
static int hf_tsp_time_sec = -1; 
static int hf_tsp_time_usec = -1; 
static int hf_tsp_name = -1; 

static gint ett_tsp = -1;

static dissector_handle_t	tsp_handle;


/* timed port from /etc/services */
#define UDP_PORT_TIMED	525


static const value_string names_tsp_type[] = {
#define TSP_ANY                 0       /* match any types */
	{	TSP_ANY, "any" },
#define TSP_ADJTIME             1       /* send adjtime */
	{	TSP_ADJTIME, "adjtime" },
#define TSP_ACK                 2       /* generic acknowledgement */
	{	TSP_ACK, "ack" },
#define TSP_MASTERREQ           3       /* ask for master's name */
	{	TSP_MASTERREQ, "masterreq" },
#define TSP_MASTERACK           4       /* acknowledge master request */
	{	TSP_MASTERACK, "masterack" },
#define TSP_SETTIME             5       /* send network time */
	{	TSP_SETTIME, "settime" },
#define TSP_MASTERUP            6       /* inform slaves that master is up */
	{	TSP_MASTERUP, "masterup" },
#define TSP_SLAVEUP             7       /* slave is up but not polled */
	{	TSP_SLAVEUP, "slaveup" },
#define TSP_ELECTION            8       /* advance candidature for master */
	{	TSP_ELECTION, "election" },
#define TSP_ACCEPT              9       /* support candidature of master */
	{	TSP_ACCEPT, "accept" },
#define TSP_REFUSE              10      /* reject candidature of master */
	{	TSP_REFUSE, "refuse" },
#define TSP_CONFLICT            11      /* two or more masters present */
	{	TSP_CONFLICT, "conflict" },
#define TSP_RESOLVE             12      /* masters' conflict resolution */
	{	TSP_RESOLVE, "resolve" },
#define TSP_QUIT                13      /* reject candidature if master is up */
	{	TSP_QUIT, "quit" },
#define TSP_DATE                14      /* reset the time (date command) */
	{	TSP_DATE, "date" },
#define TSP_DATEREQ             15      /* remote request to reset the time */
	{	TSP_DATEREQ, "datereq" },
#define TSP_DATEACK             16      /* acknowledge time setting  */
	{	TSP_DATEACK, "dateack" },
#define TSP_TRACEON             17      /* turn tracing on */
	{	TSP_TRACEON, "traceon" },
#define TSP_TRACEOFF            18      /* turn tracing off */
	{	TSP_TRACEOFF, "traceoff" },
#define TSP_MSITE               19      /* find out master's site */
	{	TSP_MSITE, "msite" },
#define TSP_MSITEREQ            20      /* remote master's site request */
	{	TSP_MSITEREQ, "msitereq" },
#define TSP_TEST                21      /* for testing election algo */
	{	TSP_TEST, "test" },
#define TSP_SETDATE             22      /* New from date command */
	{	TSP_SETDATE, "setdate" },
#define TSP_SETDATEREQ          23      /* New remote for above */
	{	TSP_SETDATEREQ, "setdatereq" },
#define TSP_LOOP                24      /* loop detection packet */
	{	TSP_LOOP, "loop" },
	{ 0, NULL }
};


static void
dissect_tsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*tsp_tree = NULL;
	proto_item	*tsp_item = NULL;

	guint8		tsp_type;
	guint8		tsp_vers;
	guint16		tsp_seq;
	guint32		tsp_time_sec;
	guint32		tsp_time_usec;
	guint8		tsp_hopcnt;
	gint		tsp_name_length;
	guint8		tsp_name[256];

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "TSP");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	tsp_type = tvb_get_guint8(tvb, 0);
	tsp_vers = tvb_get_guint8(tvb, 1);
	tsp_seq = tvb_get_ntohs(tvb, 2);

	if (tree) {
		tsp_item = proto_tree_add_item(tree, proto_tsp,
				tvb, 0, -1, FALSE);
		if (tsp_item)
			tsp_tree = proto_item_add_subtree(tsp_item, ett_tsp);
	}

	if (tsp_tree) {
		proto_tree_add_uint(tsp_tree, hf_tsp_type,
			tvb, 0, 1, tsp_type);
		proto_tree_add_uint(tsp_tree, hf_tsp_vers,
			tvb, 1, 1, tsp_vers);
		proto_tree_add_uint(tsp_tree, hf_tsp_seq,
			tvb, 2, 2, tsp_seq);
	}

	if (tsp_type == TSP_LOOP) {
		tsp_hopcnt = tvb_get_guint8(tvb, 4);
		if (tsp_tree)
			proto_tree_add_uint(tsp_tree, hf_tsp_hopcnt,
				tvb, 4, 1, tsp_type);
	}

	if (tsp_type == TSP_SETTIME ||
		tsp_type == TSP_ADJTIME ||
		tsp_type == TSP_SETDATE ||
		tsp_type == TSP_SETDATEREQ) {

		tsp_time_sec = tvb_get_ntohl(tvb, 4);
		if (tsp_tree)
			proto_tree_add_uint(tsp_tree, hf_tsp_time_sec,
				tvb, 4, 4, tsp_time_sec);
		tsp_time_usec = tvb_get_ntohl(tvb, 8);
		if (tsp_tree)
			proto_tree_add_uint(tsp_tree, hf_tsp_time_usec,
				tvb, 8, 4, tsp_time_usec);
	}

	tsp_name_length = tvb_get_nstringz(tvb, 12, 256, tsp_name);
	if (tsp_name_length>0 && tsp_tree) {
		proto_tree_add_string(tsp_tree, hf_tsp_name, tvb, 12,
			tsp_name_length, tsp_name);
	}
}


void
proto_reg_handoff_tsp(void)
{
	dissector_add("udp.port", UDP_PORT_TIMED, tsp_handle);
}


void
proto_register_tsp(void)
{
  static hf_register_info hf[] = {
    { &hf_tsp_type,
      { "Type", "tsp.type",
	FT_UINT8, BASE_DEC, VALS(names_tsp_type), 0x0,
	"Packet Type", HFILL }},
    { &hf_tsp_vers,
      { "Version", "tsp.version",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"Protocol Version Number", HFILL }},
    { &hf_tsp_seq,
      { "Sequence", "tsp.sequence",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Sequence Number", HFILL }},
    { &hf_tsp_hopcnt,
      { "Hop Count", "tsp.hopcnt",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"Hop Count", HFILL }},
    { &hf_tsp_time_sec,
      { "Seconds", "tsp.sec",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Seconds", HFILL }},
    { &hf_tsp_time_usec,
      { "Microseconds", "tsp.usec",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Microseconds", HFILL }},
    { &hf_tsp_name,
      { "Machine Name", "tsp.name",
	FT_STRING, BASE_DEC, NULL, 0x0,
	"Sender Machine Name", HFILL }}
  };
	static gint *ett[] = {
		&ett_tsp
	};

	proto_tsp = proto_register_protocol("Time Synchronization Protocol",
					"TSP", "tsp");
	proto_register_field_array(proto_tsp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	tsp_handle = create_dissector_handle(dissect_tsp, proto_tsp);
}

