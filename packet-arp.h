/* packet-arp.h
 * Definitions of routines for ARP packet disassembly that are used
 * elsewhere
 *
 * $Id: packet-arp.h,v 1.5 2001/03/13 21:34:23 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifndef __PACKET_ARP_H__
#define __PACKET_ARP_H__

gchar *arphrdaddr_to_str(const guint8 *ad, int ad_len, guint16 type);
gchar *arphrdtype_to_str(guint16 hwtype, const char *fmt);

void dissect_atm_nsap(tvbuff_t *tvb, int offset, int len, proto_tree *tree);

#endif /* packet-atm.h */
