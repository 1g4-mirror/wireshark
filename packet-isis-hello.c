/* packet-isis-hello.c
 * Routines for decoding isis hello packets and their CLVs
 *
 * $Id: packet-isis-hello.c,v 1.27 2002/02/09 23:44:38 guy Exp $
 * Stuart Stanley <stuarts@mxmail.net>
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
#include "packet-osi.h"
#include "packet-isis.h"
#include "packet-isis-clv.h"
#include "packet-isis-hello.h"
#include "epan/resolv.h"

/* hello packets */
static int hf_isis_hello_circuit_reserved    = -1;
static int hf_isis_hello_source_id           = -1;
static int hf_isis_hello_holding_timer       = -1;
static int hf_isis_hello_pdu_length          = -1;
static int hf_isis_hello_priority_reserved   = -1;
static int hf_isis_hello_lan_id              = -1;
static int hf_isis_hello_local_circuit_id    = -1;
static int hf_isis_hello_clv_ipv4_int_addr   = -1;
static int hf_isis_hello_clv_ipv6_int_addr   = -1;
static int hf_isis_hello_clv_ptp_adj         = -1;
static int hf_isis_hello_clv_mt              = -1;
static int hf_isis_hello_clv_restart         = -1;

static gint ett_isis_hello                   = -1;
static gint ett_isis_hello_clv_area_addr     = -1;
static gint ett_isis_hello_clv_is_neighbors  = -1;
static gint ett_isis_hello_clv_padding       = -1;
static gint ett_isis_hello_clv_unknown       = -1;
static gint ett_isis_hello_clv_nlpid         = -1;
static gint ett_isis_hello_clv_auth          = -1;
static gint ett_isis_hello_clv_ipv4_int_addr = -1;
static gint ett_isis_hello_clv_ipv6_int_addr = -1;
static gint ett_isis_hello_clv_ptp_adj       = -1;
static gint ett_isis_hello_clv_mt            = -1;
static gint ett_isis_hello_clv_restart       = -1;

static const value_string isis_hello_circuit_type_vals[] = {
	{ ISIS_HELLO_TYPE_RESERVED,	"Reserved 0 (discard PDU)"},
	{ ISIS_HELLO_TYPE_LEVEL_1,	"Level 1 only"},
	{ ISIS_HELLO_TYPE_LEVEL_2,	"Level 2 only"},
	{ ISIS_HELLO_TYPE_LEVEL_12,	"Level 1 and 2"},
	{ 0,		NULL} };

/* 
 * Predclare dissectors for use in clv dissection.
 */
static void dissect_hello_padding_clv(tvbuff_t *tvb, 
		packet_info *pinfo, proto_tree *tree, int offset, 
		int id_length, int length);
static void dissect_hello_is_neighbors_clv(tvbuff_t *tvb, 
		packet_info *pinfo, proto_tree *tree, int offset, 
		int id_length, int length);
static void dissect_hello_ptp_adj_clv(tvbuff_t *tvb, 
		packet_info *pinfo, proto_tree *tree, int offset, 
		int id_length, int length);
static void dissect_hello_area_address_clv(tvbuff_t *tvb, 
		packet_info *pinfo, proto_tree *tree, int offset, 
		int id_length, int length);
static void dissect_hello_auth_clv(tvbuff_t *tvb, 
		packet_info *pinfo, proto_tree *tree, int offset, 
		int id_length, int length);
static void dissect_hello_ipv6_int_addr_clv(tvbuff_t *tvb, 
		packet_info *pinfo, proto_tree *tree, int offset, 
		int id_length, int length);
static void dissect_hello_ip_int_addr_clv(tvbuff_t *tvb, 
		packet_info *pinfo, proto_tree *tree, int offset, 
		int id_length, int length);
static void dissect_hello_mt_clv(tvbuff_t *tvb, 
		packet_info *pinfo, proto_tree *tree, int offset, 
		int id_length, int length);
static void dissect_hello_nlpid_clv(tvbuff_t *tvb, 
		packet_info *pinfo, proto_tree *tree, int offset, 
		int id_length, int length);
static void dissect_hello_restart_clv(tvbuff_t *tvb, 
		packet_info *pinfo, proto_tree *tree, int offset, 
		int id_length, int length);


static const isis_clv_handle_t clv_l1_hello_opts[] = {
	{
		ISIS_CLV_L1H_AREA_ADDRESS,
		"Area address(es)",
		&ett_isis_hello_clv_area_addr,
		dissect_hello_area_address_clv
	},
	{
		ISIS_CLV_L1H_IS_NEIGHBORS,
		"IS Neighbor(s)",
		&ett_isis_hello_clv_is_neighbors,
		dissect_hello_is_neighbors_clv
	},
	{
		ISIS_CLV_L1H_PADDING,
		"Padding",
		&ett_isis_hello_clv_padding,
		dissect_hello_padding_clv
	},
	{
		ISIS_CLV_L1H_NLPID,
		"Protocols Supported",
		&ett_isis_hello_clv_nlpid,
		dissect_hello_nlpid_clv
	},
	{
		ISIS_CLV_L1H_IP_INTERFACE_ADDR,
		"IP Interface address(es)",
		&ett_isis_hello_clv_ipv4_int_addr,
		dissect_hello_ip_int_addr_clv
	},
	{
		ISIS_CLV_L1H_IPv6_INTERFACE_ADDR,
		"IPv6 Interface address(es)",
		&ett_isis_hello_clv_ipv6_int_addr,
		dissect_hello_ipv6_int_addr_clv
	},
	{
		ISIS_CLV_L1H_RESTART,
		"Restart Signaling",
		&ett_isis_hello_clv_restart,
		dissect_hello_restart_clv
	},
	{
		ISIS_CLV_L1H_AUTHENTICATION_NS,
		"Authentication(non spec)",
		&ett_isis_hello_clv_auth,
		dissect_hello_auth_clv
	},
	{
		ISIS_CLV_L1H_AUTHENTICATION,
		"Authentication",
		&ett_isis_hello_clv_auth,
		dissect_hello_auth_clv
	},
	{
		ISIS_CLV_L1H_MT,
		"Multi Topology",
		&ett_isis_hello_clv_mt,
		dissect_hello_mt_clv
	},
	{
		0,
		"",
		NULL,
		NULL
	}
};

static const isis_clv_handle_t clv_l2_hello_opts[] = {
	{
		ISIS_CLV_L2H_AREA_ADDRESS,
		"Area address(es)",
		&ett_isis_hello_clv_area_addr,
		dissect_hello_area_address_clv
	},
	{
		ISIS_CLV_L2H_IS_NEIGHBORS,
		"IS Neighbor(s)",
		&ett_isis_hello_clv_is_neighbors,
		dissect_hello_is_neighbors_clv
	},
	{
		ISIS_CLV_L2H_PADDING,
		"Padding",
		&ett_isis_hello_clv_padding,
		dissect_hello_padding_clv
	},
	{
		ISIS_CLV_L2H_NLPID,
		"Protocols Supported",
		&ett_isis_hello_clv_nlpid,
		dissect_hello_nlpid_clv
	},
	{
		ISIS_CLV_L2H_IP_INTERFACE_ADDR,
		"IP Interface address(es)",
		&ett_isis_hello_clv_ipv4_int_addr,
		dissect_hello_ip_int_addr_clv
	},
	{
		ISIS_CLV_L2H_IPv6_INTERFACE_ADDR,
		"IPv6 Interface address(es)",
		&ett_isis_hello_clv_ipv6_int_addr,
		dissect_hello_ipv6_int_addr_clv
	},
	{
		ISIS_CLV_L2H_AUTHENTICATION_NS,
		"Authentication(non spec)",
		&ett_isis_hello_clv_auth,
		dissect_hello_auth_clv
	},
	{
		ISIS_CLV_L2H_RESTART,
		"Restart Signaling",
		&ett_isis_hello_clv_restart,
		dissect_hello_restart_clv
	},
	{
		ISIS_CLV_L2H_AUTHENTICATION,
		"Authentication",
		&ett_isis_hello_clv_auth,
		dissect_hello_auth_clv
	},
	{
		ISIS_CLV_L2H_MT,
		"Multi Topology",
		&ett_isis_hello_clv_mt,
		dissect_hello_mt_clv
	},
	{
		0,
		"",
		NULL,
		NULL
	}
};

static const isis_clv_handle_t clv_ptp_hello_opts[] = {
	{
		ISIS_CLV_PTP_AREA_ADDRESS,
		"Area address(es)",
		&ett_isis_hello_clv_area_addr,
		dissect_hello_area_address_clv
	},
	{
		ISIS_CLV_PTP_PADDING,
		"Padding",
		&ett_isis_hello_clv_padding,
		dissect_hello_padding_clv
	},
	{
		ISIS_CLV_PTP_NLPID,
		"Protocols Supported",
		&ett_isis_hello_clv_nlpid,
		dissect_hello_nlpid_clv
	},
	{
		ISIS_CLV_PTP_IP_INTERFACE_ADDR,
		"IP Interface address(es)",
		&ett_isis_hello_clv_ipv4_int_addr,
		dissect_hello_ip_int_addr_clv
	},
	{
		ISIS_CLV_PTP_IPv6_INTERFACE_ADDR,
		"IPv6 Interface address(es)",
		&ett_isis_hello_clv_ipv6_int_addr,
		dissect_hello_ipv6_int_addr_clv
	},
	{
		ISIS_CLV_PTP_AUTHENTICATION_NS,
		"Authentication(non spec)",
		&ett_isis_hello_clv_auth,
		dissect_hello_auth_clv
	},
	{
		ISIS_CLV_PTP_AUTHENTICATION,
		"Authentication",
		&ett_isis_hello_clv_auth,
		dissect_hello_auth_clv
	},
	{
		ISIS_CLV_PTP_RESTART,
		"Restart Option",
		&ett_isis_hello_clv_restart,
		dissect_hello_restart_clv
	},
	{
		ISIS_CLV_PTP_ADJ,
		"Point-to-point Adjacency State",
		&ett_isis_hello_clv_ptp_adj,
		dissect_hello_ptp_adj_clv
	},
	{
		ISIS_CLV_PTP_MT,
		"Multi Topology",
		&ett_isis_hello_clv_mt,
		dissect_hello_mt_clv
	},
	{
		0,
		"",
		NULL,
		NULL
	}
};


/*
 * Name: dissect_hello_restart_clv()
 *
 * Description:
 *	Decode for a restart clv - only found in IIHs
 *      hence no call in the common clv dissector
 *
 */

static void 
dissect_hello_restart_clv(tvbuff_t *tvb, 
		packet_info *pinfo, proto_tree *tree, int offset, 
		int id_length, int length)
{
	int restart_options;

	restart_options = tvb_get_guint8(tvb, offset);

	proto_tree_add_text ( tree, tvb, offset, 1,        
			      "Restart Request bit %s, "
			      "Restart Acknowledgement bit %s",
			      ISIS_MASK_RESTART_RR(restart_options) ? "set" : "clear",
			      ISIS_MASK_RESTART_RA(restart_options) ? "set" : "clear"); 
	proto_tree_add_text ( tree, tvb, offset+1, 2,        
			      "Remaining holding time: %us",
			      tvb_get_ntohs(tvb, offset+1) );
}

/*
 * Name: dissect_hello_nlpid_clv()
 *
 * Description:
 *	Decode for a hello packets NLPID clv.  Calls into the
 *	clv common one.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	packet_info * : info for current packet
 *	proto_tree * : proto tree to build on (may be null)
 *	int : current offset into packet data
 *	int : length of IDs in packet.
 *	int : length of this clv
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void 
dissect_hello_nlpid_clv(tvbuff_t *tvb, 
	packet_info *pinfo, proto_tree *tree, int offset, 
	int id_length, int length)
{
	isis_dissect_nlpid_clv(tvb, pinfo, tree, offset, length);
}

/*
 * Name: dissect_hello_mt_clv()
 *
 * Description:
 *	Decode for a hello packets Multi Topology clv.  Calls into the
 *	clv common one.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	packet_info * : info for current packet
 *	proto_tree * : proto tree to build on (may be null)
 *	int : current offset into packet data
 *	int : length of IDs in packet.
 *	int : length of this clv
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */

static void 
dissect_hello_mt_clv(tvbuff_t *tvb, 
	packet_info *pinfo, proto_tree *tree, int offset, 
	int id_length, int length)
{
	isis_dissect_mt_clv(tvb, pinfo, tree, offset, length,
		hf_isis_hello_clv_mt );
}

/*
 * Name: dissect_hello_ip_int_addr_clv()
 *
 * Description:
 *	Decode for a hello packets ip interface addr clv.  Calls into the
 *	clv common one.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	packet_info * : info for current packet
 *	proto_tree * : proto tree to build on (may be null)
 *	int : current offset into packet data
 *	int : length of IDs in packet.
 *	int : length of this clv
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void 
dissect_hello_ip_int_addr_clv(tvbuff_t *tvb, 
	packet_info *pinfo, proto_tree *tree, int offset, 
	int id_length, int length)
{
	isis_dissect_ip_int_clv(tvb, pinfo, tree, offset, length,
		hf_isis_hello_clv_ipv4_int_addr );
}

/*
 * Name: dissect_hello_ipv6_int_addr_clv()
 *
 * Description:
 *	Decode for a hello packets ipv6 interface addr clv.  Calls into the
 *	clv common one.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	packet_info * : info for current packet
 *	proto_tree * : proto tree to build on (may be null)
 *	int : current offset into packet data
 *	int : length of IDs in packet.
 *	int : length of this clv
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void 
dissect_hello_ipv6_int_addr_clv(tvbuff_t *tvb, 
	packet_info *pinfo, proto_tree *tree, int offset, 
	int id_length, int length)
{
	isis_dissect_ipv6_int_clv(tvb, pinfo, tree, offset, length,
		hf_isis_hello_clv_ipv6_int_addr );
}

/*
 * Name: dissect_hello_auth_clv()
 *
 * Description:
 *	Decode for a hello packets authenticaion clv.  Calls into the
 *	clv common one.  An auth inside a hello packet is a perlink
 *	password.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	packet_info * : info for current packet
 *	proto_tree * : proto tree to build on (may be null)
 *	int : current offset into packet data
 *	int : length of IDs in packet.
 *	int : length of this clv
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void 
dissect_hello_auth_clv(tvbuff_t *tvb, 
	packet_info *pinfo, proto_tree *tree, int offset, 
	int id_length, int length)
{
	isis_dissect_authentication_clv(tvb, pinfo, tree, offset,
		length, "authentication" );
}

/*
 * Name: dissect_hello_area_address_clv()
 *
 * Description:
 *	Decode for a hello packets area address clv.  Calls into the
 *	clv common one.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	packet_info * : info for current packet
 *	proto_tree * : proto tree to build on (may be null)
 *	int : current offset into packet data
 *	int : length of IDs in packet.
 *	int : length of this clv
 *
 * Output:
 *	void, will modify proto_tree if not null.
 */
static void 
dissect_hello_area_address_clv(tvbuff_t *tvb, 
	packet_info *pinfo, proto_tree *tree, int offset, 
	int id_length, int length)
{
	isis_dissect_area_address_clv(tvb, pinfo, tree, offset, length);
}



static void 
dissect_hello_ptp_adj_clv(tvbuff_t *tvb, 
		packet_info *pinfo, proto_tree *tree, int offset, 
		int id_length, int length)
{
	char adj_state[20];

	switch(tvb_get_guint8(tvb, offset)) {
	  case 0:
	    strcpy(adj_state,"Up");
	    break;
	  case 1:
	    strcpy(adj_state,"Initializing");
	    break;
	  case 2:
	    strcpy(adj_state,"Down");
	    break;
	  default:
	    strcpy(adj_state,"<illegal value !!!>");
	    }

	switch(length) {
	  case 1:
	    proto_tree_add_text ( tree, tvb, offset, 1,
				  "Adjacency State: %s", adj_state );
	    break;
	  case 5:
	    proto_tree_add_text ( tree, tvb, offset, 1,        
                                  "Adjacency State: %s", adj_state ); 
	    proto_tree_add_text ( tree, tvb, offset+1, 4,        
                                  "Extended Local circuit ID: 0x%08x", tvb_get_ntohl(tvb, offset+1) ); 
	    break;
	  case 11:
            proto_tree_add_text ( tree, tvb, offset, 1,
                                  "Adjacency State: %s", adj_state );
            proto_tree_add_text ( tree, tvb, offset+1, 4,
                                  "Extended Local circuit ID: 0x%08x", tvb_get_ntohl(tvb, offset+1) );
            proto_tree_add_text ( tree, tvb, offset+5, 6,
                                  "Neighbor SystemID: %s", print_system_id( tvb_get_ptr(tvb, offset+5, 6), 6 ) );
	    break;
	  case 15:
	    proto_tree_add_text ( tree, tvb, offset, 1,
                                  "Adjacency State: %s", adj_state );
            proto_tree_add_text ( tree, tvb, offset+1, 4,
                                  "Extended Local circuit ID: 0x%08x", tvb_get_ntohl(tvb, offset+1) );
            proto_tree_add_text ( tree, tvb, offset+5, 6,
                                  "Neighbor SystemID: %s", print_system_id( tvb_get_ptr(tvb, offset+5, 6), 6 ) );  
            proto_tree_add_text ( tree, tvb, offset+11, 4,
                                  "Neighbor Extended Local circuit ID: 0x%08x", tvb_get_ntohl(tvb, offset+11) );
	    break;
	  default:
	    isis_dissect_unknown(tvb, pinfo, tree, offset,
				 "malformed TLV (%d vs 1,5,11,15)", length );
	    return;
	}
}

/*
 * Name: isis_dissect_is_neighbors_clv()
 * 
 * Description:
 *	Take apart a IS neighbor packet.  A neighbor is n 6 byte packets.
 *	(they tend to be an 802.3 MAC address, but its not required).
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	packet_info * : info for current packet
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	int : length of IDs in packet.
 *	int : length of clv we are decoding
 * 
 * Output:
 *	void, but we will add to proto tree if !NULL.
 */
static void 
dissect_hello_is_neighbors_clv(tvbuff_t *tvb, packet_info *pinfo,
		proto_tree *tree, int offset, int id_length, int length)
{
	while ( length > 0 ) {
		if (length<6) {
			isis_dissect_unknown(tvb, pinfo, tree, offset,
				"short is neighbor (%d vs 6)", length );
			return;
		}
		/* 
		 * Lets turn the area address into "standard" 0000.0000.etc
		 * format string.  
		 */
		if ( tree ) {
			proto_tree_add_text ( tree, tvb, offset, 6, 
				"IS Neighbor: %s", get_ether_name( tvb_get_ptr(tvb, offset, 6)) );
		}
		offset += 6;
		length -= 6;
	}
}

/*
 * Name: dissect_hello_padding_clv()
 *
 * Description:
 *	Decode for a hello packet's padding clv.  Padding does nothing,
 *	so we just return.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	packet_info * : info for current packet
 *	proto_tree * : proto tree to build on (may be null)
 *	int : current offset into packet data
 *	int : length of IDs in packet.
 *	int : length of this clv
 *
 * Output:
 *	void
 */
static void 
dissect_hello_padding_clv(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int offset, int id_length, int length)
{
	/* nothing to do here! */
}


/*
 * Name: isis_dissect_isis_hello()
 * 
 * Description:
 *	This procedure rips apart the various types of ISIS hellos.  L1H and
 *	L2H's are identical for the most part, while the PTP hello has
 *	a shorter header.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	packet_info * : info for current packet
 *	proto_tree * : protocol display tree to add to.  May be NULL.
 *	int offset : our offset into packet data.
 *	int : hello type, a la packet-isis.h ISIS_TYPE_* values
 *	int : header length of packet.
 *	int : length of IDs in packet.
 *
 * Output:
 *	void, will modify proto_tree if not NULL.
 */	
void 
isis_dissect_isis_hello(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	int offset, int hello_type, int header_length, int id_length)
{
	proto_item	*ti;
	proto_tree	*hello_tree = NULL;
	int 		len;
	guint8		octet;
	const guint8	*source_id;
	guint16		pdu_length;
	const guint8	*lan_id;

	if (tree) {
		ti = proto_tree_add_text(tree, tvb, offset, -1, "ISIS HELLO");
		hello_tree = proto_item_add_subtree(ti, ett_isis_hello);
		octet = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint_format(hello_tree,
			hf_isis_hello_circuit_reserved,
			tvb, offset, 1, octet,
			"Circuit type              : %s, reserved(0x%02x == 0)",
				val_to_str(octet&ISIS_HELLO_CTYPE_MASK,
					isis_hello_circuit_type_vals,
					"Unknown (0x%x)"),
				octet&ISIS_HELLO_CT_RESERVED_MASK
			);
	}
	offset += 1;

	if (tree) {
		source_id = tvb_get_ptr(tvb, offset, id_length);
		proto_tree_add_bytes_format(hello_tree, hf_isis_hello_source_id, tvb,
			            offset, id_length, source_id,
			            "SystemID{ Sender of PDU } : %s", 
			            print_system_id( source_id, id_length ) );
        }
	offset += id_length;

	if (tree) {
		proto_tree_add_item(hello_tree, hf_isis_hello_holding_timer, tvb,
			            offset, 2, FALSE);
	}
	offset += 2;

	pdu_length = tvb_get_ntohs(tvb, offset);
	if (tree) {
		proto_tree_add_uint(hello_tree, hf_isis_hello_pdu_length, tvb,
			            offset, 2, pdu_length);
	}
	offset += 2;

	if (hello_type == ISIS_TYPE_PTP_HELLO) {
		if (tree) {
			proto_tree_add_item(hello_tree, hf_isis_hello_local_circuit_id, tvb,
				         offset, 1, FALSE );
		}
		offset += 1;
	} else { 

                if (tree) {
                        octet = tvb_get_guint8(tvb, offset);
                        proto_tree_add_uint_format(hello_tree, hf_isis_hello_priority_reserved, tvb,
                                    offset, 1, octet,
                                    "Priority                  : %d, reserved(0x%02x == 0)",
                                        octet&ISIS_HELLO_PRIORITY_MASK,
                                        octet&ISIS_HELLO_P_RESERVED_MASK );
                }
                offset += 1;

		if (tree) {
			lan_id = tvb_get_ptr(tvb, offset, id_length+1);
			proto_tree_add_bytes_format(hello_tree, hf_isis_hello_lan_id, tvb, 
		                     offset, id_length + 1, lan_id,
				         "SystemID{ Designated IS } : %s",
					      print_system_id( lan_id, id_length + 1 ) );
		}
		offset += id_length + 1;
	}

	len = pdu_length;
	len -= header_length;
	if (len < 0) {
		isis_dissect_unknown(tvb, pinfo, tree, offset,
			"Packet header length %d went beyond packet", 
			header_length );
		return;
	}
	/*
	 * Now, we need to decode our CLVs.  We need to pass in
	 * our list of valid ones!
	 */
	if (hello_type == ISIS_TYPE_L1_HELLO){
		isis_dissect_clvs(tvb, pinfo, hello_tree, offset,
			clv_l1_hello_opts, len, id_length,
			ett_isis_hello_clv_unknown);
	} else if (hello_type == ISIS_TYPE_L2_HELLO) {
		isis_dissect_clvs(tvb, pinfo, hello_tree, offset,
			clv_l2_hello_opts, len, id_length,
			ett_isis_hello_clv_unknown);
	} else {
		isis_dissect_clvs(tvb, pinfo, hello_tree, offset,
			clv_ptp_hello_opts, len, id_length,
			ett_isis_hello_clv_unknown);
	}
}

/*
 * Name: isis_register_hello()
 *
 * Description:
 *	Register our protocol sub-sets with protocol manager.
 *
 * Input: 
 *	int : protocol index for the ISIS protocol
 *
 * Output:
 *	void
 */
void
isis_register_hello(int proto_isis) {
	static hf_register_info hf[] = {
		{ &hf_isis_hello_circuit_reserved,
		{ "Circuit type              ", "isis.hello.circuit_type",
			FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},

		{ &hf_isis_hello_source_id,
		{ "SystemID{ Sender of PDU } ", "isis.hello.source_id",
			FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }},

		{ &hf_isis_hello_holding_timer,
		{ "Holding timer             ", "isis.hello.holding_timer", 
			FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},

		{ &hf_isis_hello_pdu_length,
		{ "PDU length                ", "isis.hello.pdu_length",
			FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},

		{ &hf_isis_hello_priority_reserved,
		 { "Priority                 ", "isis.hello.priority",
			FT_UINT8, BASE_DEC, NULL, ISIS_HELLO_P_RESERVED_MASK, "", HFILL }},

		{ &hf_isis_hello_lan_id,
		{ "SystemID{ Designated IS } ", "isis.hello.lan_id",
			FT_BYTES, BASE_DEC, NULL, 0x0, "", HFILL }},

		{ &hf_isis_hello_local_circuit_id,
		{ "Local circuit ID          ", "isis.hello.local_circuit_id",
			FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},

		{ &hf_isis_hello_clv_ipv4_int_addr,
		{ "IPv4 interface address    ", "isis.hello.clv_ipv4_int_addr",
			FT_IPv4, BASE_NONE, NULL, 0x0, "", HFILL }},

		{ &hf_isis_hello_clv_ipv6_int_addr,
		{ "IPv6 interface address    ", "isis.hello.clv_ipv6_int_addr",
			FT_IPv6, BASE_NONE, NULL, 0x0, "", HFILL }},

		{ &hf_isis_hello_clv_ptp_adj,
		{ "Point-to-point Adjacency  ", "isis.hello.clv_ptp_adj",
			FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},

	};
	static gint *ett[] = {
		&ett_isis_hello,
		&ett_isis_hello_clv_area_addr,
		&ett_isis_hello_clv_is_neighbors,
		&ett_isis_hello_clv_padding,
		&ett_isis_hello_clv_unknown,
		&ett_isis_hello_clv_nlpid,
		&ett_isis_hello_clv_auth,
		&ett_isis_hello_clv_ipv4_int_addr,
		&ett_isis_hello_clv_ipv6_int_addr,
		&ett_isis_hello_clv_ptp_adj,
		&ett_isis_hello_clv_mt,
		&ett_isis_hello_clv_restart
	};

	proto_register_field_array(proto_isis, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
