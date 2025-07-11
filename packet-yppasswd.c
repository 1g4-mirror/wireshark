/* packet-yppasswd.c
 * Routines for yppasswd dissection
 *
 * $Id: packet-yppasswd.c,v 1.5 2002/01/24 09:20:54 guy Exp $
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
#include "config.h"
#endif


#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif


#include "packet-rpc.h"
#include "packet-yppasswd.h"

static int proto_yppasswd = -1;
static int hf_yppasswd_status = -1;
static int hf_yppasswd_oldpass = -1;
static int hf_yppasswd_newpw = -1;
static int hf_yppasswd_newpw_name = -1;
static int hf_yppasswd_newpw_passwd = -1;
static int hf_yppasswd_newpw_uid = -1;
static int hf_yppasswd_newpw_gid = -1;
static int hf_yppasswd_newpw_gecos = -1;
static int hf_yppasswd_newpw_dir = -1;
static int hf_yppasswd_newpw_shell = -1;

static gint ett_yppasswd = -1;
static gint ett_yppasswd_newpw = -1;

static int
dissect_yppasswd_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item *lock_item = NULL;
	proto_tree *lock_tree = NULL;

	offset = dissect_rpc_string(tvb, pinfo, tree, hf_yppasswd_oldpass, 
			offset, NULL);

	lock_item = proto_tree_add_item(tree, hf_yppasswd_newpw, tvb,
			offset, -1, FALSE);

	lock_tree = proto_item_add_subtree(lock_item, ett_yppasswd_newpw);

	offset = dissect_rpc_string(tvb, pinfo, lock_tree, 
			hf_yppasswd_newpw_name, offset, NULL);
	offset = dissect_rpc_string(tvb, pinfo, lock_tree, 
			hf_yppasswd_newpw_passwd, offset, NULL);
	offset = dissect_rpc_uint32(tvb, pinfo, lock_tree, 
			hf_yppasswd_newpw_uid, offset);
	offset = dissect_rpc_uint32(tvb, pinfo, lock_tree, 
			hf_yppasswd_newpw_gid, offset);
	offset = dissect_rpc_string(tvb, pinfo, lock_tree, 
			hf_yppasswd_newpw_gecos, offset, NULL);
	offset = dissect_rpc_string(tvb, pinfo, lock_tree, 
			hf_yppasswd_newpw_dir, offset, NULL);
	offset = dissect_rpc_string(tvb, pinfo, lock_tree, 
			hf_yppasswd_newpw_shell, offset, NULL);

	return offset;
}

static int
dissect_yppasswd_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, pinfo, tree, hf_yppasswd_status, offset);

	return offset;
}

/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */
static const vsff yppasswd1_proc[] = {
	{ YPPASSWDPROC_UPDATE,	"UPDATE",
		dissect_yppasswd_call,	dissect_yppasswd_reply },
	{ 0,	NULL,		NULL,				NULL }
};

void
proto_register_yppasswd(void)
{
	static hf_register_info hf[] = {
		{ &hf_yppasswd_status, {
			"status", "yppasswd.status", FT_UINT32, BASE_DEC,
			NULL, 0, "YPPasswd update status", HFILL }},

		{ &hf_yppasswd_oldpass, {
			"oldpass", "yppasswd.oldpass", FT_STRING, BASE_DEC,
			NULL, 0, "Old encrypted password", HFILL }},

		{ &hf_yppasswd_newpw, {
			"newpw", "yppasswd.newpw", FT_NONE, 0,
			NULL, 0, "New passwd entry", HFILL }},

		{ &hf_yppasswd_newpw_name, {
			"name", "yppasswd.newpw.name", FT_STRING, BASE_DEC,
			NULL, 0, "Username", HFILL }},

		{ &hf_yppasswd_newpw_passwd, {
			"passwd", "yppasswd.newpw.passwd", FT_STRING, BASE_DEC,
			NULL, 0, "Encrypted passwd", HFILL }},

		{ &hf_yppasswd_newpw_uid, {
			"uid", "yppasswd.newpw.uid", FT_UINT32, BASE_DEC,
			NULL, 0, "UserID", HFILL }},

		{ &hf_yppasswd_newpw_gid, {
			"gid", "yppasswd.newpw.gid", FT_UINT32, BASE_DEC,
			NULL, 0, "GroupID", HFILL }},

		{ &hf_yppasswd_newpw_gecos, {
			"gecos", "yppasswd.newpw.gecos", FT_STRING, BASE_DEC,
			NULL, 0, "In real life name", HFILL }},

		{ &hf_yppasswd_newpw_dir, {
			"dir", "yppasswd.newpw.dir", FT_STRING, BASE_DEC,
			NULL, 0, "Home Directory", HFILL }},

		{ &hf_yppasswd_newpw_shell, {
			"shell", "yppasswd.newpw.shell", FT_STRING, BASE_DEC,
			NULL, 0, "Default shell", HFILL }},

	};

	static gint *ett[] = {
		&ett_yppasswd,
		&ett_yppasswd_newpw,
	};

	proto_yppasswd = proto_register_protocol("Yellow Pages Passwd",
	    "YPPASSWD", "yppasswd");
	proto_register_field_array(proto_yppasswd, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_yppasswd(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_yppasswd, YPPASSWD_PROGRAM, ett_yppasswd);
	/* Register the procedure tables */
	rpc_init_proc_table(YPPASSWD_PROGRAM, 1, yppasswd1_proc);
}

