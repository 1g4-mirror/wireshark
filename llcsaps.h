/* llcsaps.h
 * Defines LLC SAP values.
 *
 * $Id: llcsaps.h,v 1.2 2001/01/05 19:07:37 guy Exp $
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

#ifndef __LLCSAPS_H__
#define __LLCSAPS_H__

#define	SAP_NULL		0x00
#define	SAP_LLC_SLMGMT		0x02
#define	SAP_SNA_PATHCTRL	0x04
#define	SAP_IP			0x06
#define	SAP_SNA1		0x08
#define	SAP_SNA2		0x0C
#define	SAP_PROWAY_NM_INIT	0x0E
#define	SAP_TI			0x18
#define	SAP_BPDU		0x42
#define	SAP_RS511		0x4E
#define	SAP_X25                 0x7E
#define	SAP_XNS			0x80
#define	SAP_NESTAR		0x86
#define	SAP_PROWAY_ASLM		0x8E
#define	SAP_ARP			0x98
#define	SAP_SNAP		0xAA
#define	SAP_ARP			0x98
#define	SAP_VINES1		0xBA
#define	SAP_VINES2		0xBC
#define	SAP_NETWARE		0xE0
#define	SAP_NETBIOS		0xF0
#define	SAP_IBMNM		0xF4
#define	SAP_RPL1		0xF8
#define	SAP_UB			0xFA
#define	SAP_RPL2		0xFC
#define	SAP_OSINL		0xFE
#define	SAP_GLOBAL		0xFF

#endif /* llcsaps.h */
