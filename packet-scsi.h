/* packet-scsi.h
 * Author: Dinesh G Dutt (ddutt@cisco.com)
 *
 * $Id: packet-scsi.h,v 1.3 2002/02/13 01:17:58 guy Exp $
 * 
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 2002 Gerald Combs
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

#ifndef __PACKET_SCSI_H_
#define __PACKET_SCSI_H_

extern const value_string scsi_status_val[];

/* Function Decls; functions invoked by SAM-2 transport protocols such as
 * FCP/iSCSI
 */
void dissect_scsi_cdb (tvbuff_t *, packet_info *, proto_tree *, guint, guint);
void dissect_scsi_rsp (tvbuff_t *, packet_info *, proto_tree *);
void dissect_scsi_payload (tvbuff_t *, packet_info *, proto_tree *, guint,
                           gboolean, guint32);
void dissect_scsi_snsinfo (tvbuff_t *, packet_info *, proto_tree *, guint, guint);

/*
 * Private data to be supplied to those functions via "pinfo->private_data";
 * the structure contains a 32-bit conversation ID and a 32-bit task
 * ID, where the former identifies a conversation between initiator and
 * target and the latter identifies a SCSI task within that conversation.
 */
typedef struct {
	guint32	conv_id;
	guint32 task_id;
} scsi_task_id_t;

#endif
