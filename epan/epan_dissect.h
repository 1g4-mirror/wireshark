/* epan_dissect.h
 *
 * $Id: epan_dissect.h,v 1.1 2001/12/18 19:09:03 gram Exp $
 *
 * Ethereal Protocol Analyzer Library
 *
 * Copyright (c) 2001 by Gerald Combs <gerald@ethereal.com>
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

#ifndef EPAN_DISSECT_H
#define EPAN_DISSECT_H

#include "tvbuff.h"
#include "proto.h"
#include "packet_info.h"

/* Dissection of a single byte array. Holds tvbuff info as
 * well as proto_tree info. As long as the epan_dissect_t for a byte
 * array is in existence, you must not free or move that byte array,
 * as the structures that the epan_dissect_t contains might have pointers
 * to addresses in your byte array.
 */
struct _epan_dissect_t {
	tvbuff_t	*tvb;
	proto_tree	*tree;
	packet_info	pi;
};


#endif /* EPAN_DISSECT_H */
