/* packet-tpkt.h
 *
 * Routines for TPKT dissection
 *
 * Copyright 2000, Philips Electronics N.V.
 * Andreas Sikkema <andreas.sikkema@philips.com>
 *
 * $Id: packet-tpkt.h,v 1.5 2002/02/02 02:51:20 guy Exp $
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

/*
 * Check whether this could be a TPKT-encapsulated PDU.
 * Returns -1 if it's not.
 * Sets "*offset" to the offset of the first byte past the TPKT header,
 * and returns the length from the TPKT header, if it is.
 */
int is_tpkt( tvbuff_t *tvb, int *offset );


/*
 * Dissect the TPKT header; called from the TPKT dissector, as well as
 * from dissectors such as the dissector for Q.931-over-TCP.
 *
 * Returns -1 if TPKT isn't enabled, otherwise returns the PDU length
 * from the TPKT header.
 */
int dissect_tpkt_header( tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree );
