/* nlpid.h
 * Definitions of OSI NLPIDs (Network Layer Protocol IDs)
 * Laurent Deniel <deniel@worldnet.fr>
 *
 * $Id: nlpid.h,v 1.10 2001/12/02 00:07:46 guy Exp $
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

#ifndef __NLPID_H__
#define __NLPID_H__

/* X.263 / ISO/IEC TR 9577 NLPID values. */

#define NLPID_NULL		0x00
#define NLPID_IPI_T_70		0x01	/* T.70, when an IPI */
#define NLPID_SPI_X_29		0x01	/* X.29, when an SPI */
#define NLPID_X_633		0x03	/* X.633 */
#define NLPID_Q_931		0x08	/* Q.931, Q.932, Q.933, X.36, ISO 11572, ISO 11582 */
#define NLPID_Q_2931		0x09	/* Q.2931 */
#define NLPID_Q_2119		0x0c	/* Q.2119 */
#define NLPID_SNAP		0x80
#define NLPID_ISO8473_CLNP	0x81	/* X.233 */
#define NLPID_ISO9542_ESIS	0x82
#define NLPID_ISO10589_ISIS	0x83
#define NLPID_ISO10747_IDRP     0x85
#define NLPID_ISO9542X25_ESIS	0x8a
#define NLPID_ISO10030		0x8c
#define NLPID_ISO11577		0x8d	/* X.273 */
#define NLPID_IP6		0x8e
#define NLPID_COMPRESSED	0xb0	/* "Data compression protocol" */
#define NLPID_IP		0xcc
#define NLPID_PPP		0xcf

extern const value_string nlpid_vals[];

/*
 * 0x09 is, in Frame Relay, LMI, Q.2931.
 */
#define NLPID_LMI		0x09	/* LMI */

#endif
