/* packet-nntp.c
 * Routines for nntp packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-nntp.c,v 1.24 2002/01/24 09:20:50 guy Exp $
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

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>

static int proto_nntp = -1;
static int hf_nntp_response = -1;
static int hf_nntp_request = -1;

static gint ett_nntp = -1;

#define TCP_PORT_NNTP			119

static void
dissect_nntp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        gchar           *type;
	proto_tree	*nntp_tree;
	proto_item	*ti;
	gint		offset = 0;
	gint		next_offset;
	int		linelen;

        if (pinfo->match_port == pinfo->destport)
        	type = "Request";
        else
        	type = "Response";

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "NNTP");

	if (check_col(pinfo->cinfo, COL_INFO)) {
		/*
		 * Put the first line from the buffer into the summary
		 * (but leave out the line terminator).
		 *
		 * Note that "tvb_find_line_end()" will return a value that
		 * is not longer than what's in the buffer, so the
		 * "tvb_get_ptr()" call won't throw an exception.
		 */
		linelen = tvb_find_line_end(tvb, offset, -1, &next_offset);
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s", type,
		    tvb_format_text(tvb, offset, linelen));
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_nntp, tvb, offset, -1,
		    FALSE);
		nntp_tree = proto_item_add_subtree(ti, ett_nntp);

		if (pinfo->match_port == pinfo->destport) {
			proto_tree_add_boolean_hidden(nntp_tree,
			    hf_nntp_request, tvb, 0, 0, TRUE);
		} else {
			proto_tree_add_boolean_hidden(nntp_tree,
			    hf_nntp_response, tvb, 0, 0, TRUE);
		}

		/*
		 * Show the request or response as text, a line at a time.
		 * XXX - for requests, we could display the stuff after the
		 * first line, if any, based on what the request was, and
		 * for responses, we could display it based on what the
		 * matching request was, although the latter requires us to
		 * know what the matching request was....
		 */
		while (tvb_offset_exists(tvb, offset)) {
			/*
			 * Find the end of the line.
			 */
			tvb_find_line_end(tvb, offset, -1, &next_offset);

			/*
			 * Put this line.
			 */
			proto_tree_add_text(nntp_tree, tvb, offset,
			    next_offset - offset, "%s",
			    tvb_format_text(tvb, offset, next_offset - offset));
			offset = next_offset;
		}
	}
}

void
proto_register_nntp(void)
{
	static hf_register_info hf[] = {
	    { &hf_nntp_response,
	      { "Response",           "nntp.response",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	      	"TRUE if NNTP response", HFILL }},

	    { &hf_nntp_request,
	      { "Request",            "nntp.request",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	      	"TRUE if NNTP request", HFILL }}
	};
	static gint *ett[] = {
		&ett_nntp,
	};

	proto_nntp = proto_register_protocol("Network News Transfer Protocol", 
	    "NNTP", "nntp");
	proto_register_field_array(proto_nntp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_nntp(void)
{
	dissector_handle_t nntp_handle;

	nntp_handle = create_dissector_handle(dissect_nntp, proto_nntp);
	dissector_add("tcp.port", TCP_PORT_NNTP, nntp_handle);
}
