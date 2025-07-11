/* packet-mount.c
 * Routines for mount dissection
 *
 * $Id: packet-mount.c,v 1.29 2002/01/20 22:12:26 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-smb.c
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

#include <string.h>

#include "packet-rpc.h"
#include "packet-mount.h"
#include "packet-nfs.h"


static int proto_mount = -1;
static int hf_mount_path = -1;
static int hf_mount3_status = -1;
static int hf_mount_mountlist_hostname = -1;
static int hf_mount_mountlist_directory = -1;
static int hf_mount_mountlist = -1;
static int hf_mount_groups_group = -1;
static int hf_mount_groups = -1;
static int hf_mount_exportlist_directory = -1;
static int hf_mount_exportlist = -1;
static int hf_mount_pathconf_link_max = -1;
static int hf_mount_pathconf_max_canon = -1;
static int hf_mount_pathconf_max_input = -1;
static int hf_mount_pathconf_name_max = -1;
static int hf_mount_pathconf_path_max = -1;
static int hf_mount_pathconf_pipe_buf = -1;
static int hf_mount_pathconf_vdisable = -1;
static int hf_mount_pathconf_mask = -1;
static int hf_mount_pathconf_error_all = -1;
static int hf_mount_pathconf_error_link_max = -1;
static int hf_mount_pathconf_error_max_canon = -1;
static int hf_mount_pathconf_error_max_input = -1;
static int hf_mount_pathconf_error_name_max = -1;
static int hf_mount_pathconf_error_path_max = -1;
static int hf_mount_pathconf_error_pipe_buf = -1;
static int hf_mount_pathconf_chown_restricted = -1;
static int hf_mount_pathconf_no_trunc = -1;
static int hf_mount_pathconf_error_vdisable = -1;
static int hf_mount_flavors = -1;
static int hf_mount_flavor = -1;

static gint ett_mount = -1;
static gint ett_mount_mountlist = -1;
static gint ett_mount_groups = -1;
static gint ett_mount_exportlist = -1;
static gint ett_mount_pathconf_mask = -1;

#define MAX_GROUP_NAME_LIST 128
static char group_name_list[MAX_GROUP_NAME_LIST];
static int  group_names_len;

/* RFC 1094, Page 24 */
/* This function dissects fhstatus for v1 and v2 of the mount protocol.
 * Formally, hf_mount3_status only define the status codes returned by version
 * 3 of the protocol. 
 * Though not formally defined in the standard, we use the same 
 * value-to-string mappings as version 3 since we belive that this mapping 
 * is consistant with most v1 and v2 implementations.
 */
static int
dissect_fhstatus(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	gint32 status;

	status=tvb_get_ntohl(tvb,offset);
	offset = dissect_rpc_uint32(tvb,pinfo,tree,hf_mount3_status,offset);

	switch (status) {
		case 0:
			offset = dissect_fhandle(tvb,offset,pinfo,tree,"fhandle");
		break;
		default:
			/* void */
		break;
	}

	return offset;
}


static int
dissect_mount_dirpath_call(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	if((!pinfo->fd->flags.visited) && nfs_file_name_snooping){
		rpc_call_info_value *civ=pinfo->private_data;

		if(civ->request && (civ->proc==1)){
			unsigned char *host, *name;
			int len;

			host=ip_to_str(pinfo->dst.data);
			len=tvb_get_ntohl(tvb, offset);
		
			name=g_malloc(strlen(host)+1+len+1);
			sprintf(name,"%s:%*s", host, len, tvb_get_ptr(tvb, offset+4, len));

			nfs_name_snoop_add_name(civ->xid, tvb, -1, strlen(name), 0, 0, name);
		}
	}


	if ( tree )
	{
		offset = dissect_rpc_string(tvb,pinfo,tree,hf_mount_path,offset,NULL);
	}
	
	return offset;
}


/* RFC 1094, Page 25,26 */
static int
dissect_mount1_mnt_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset = dissect_fhstatus(tvb,offset,pinfo,tree);

	return offset;
}



/* RFC 1094, Page 26 */
/* RFC 1813, Page 110 */
static int
dissect_mountlist(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item* lock_item = NULL;
	proto_tree* lock_tree = NULL;
	int old_offset = offset;
	char* hostname;
	char* directory;

	if (tree) {
		lock_item = proto_tree_add_item(tree, hf_mount_mountlist, tvb,
					offset, -1, FALSE);
		if (lock_item)
			lock_tree = proto_item_add_subtree(lock_item, ett_mount_mountlist);
	}

	offset = dissect_rpc_string(tvb, pinfo, lock_tree, 
			hf_mount_mountlist_hostname, offset, &hostname);
	offset = dissect_rpc_string(tvb, pinfo, lock_tree,
			hf_mount_mountlist_directory, offset, &directory);

	if (lock_item) {
		/* now we have a nicer string */
		proto_item_set_text(lock_item, "Mount List Entry: %s:%s", hostname, directory);
		/* now we know, that mountlist is shorter */
		proto_item_set_len(lock_item, offset - old_offset);
	}
	g_free(hostname);
	g_free(directory);

	return offset;
}


/* RFC 1094, Page 26 */
/* RFC 1813, Page 110 */
static int
dissect_mount_dump_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset = dissect_rpc_list(tvb, pinfo, tree, offset, dissect_mountlist);

	return offset;
}



/* RFC 1094, Page 26 */
/* RFC 1813, Page 110 */
static int
dissect_group(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	int len,str_len;
	len=tvb_get_ntohl(tvb,offset);
	str_len=tvb_get_nstringz(tvb,offset+4,
		MAX_GROUP_NAME_LIST-5-group_names_len,
		group_name_list+group_names_len);
	if((group_names_len>=(MAX_GROUP_NAME_LIST-5))||(str_len<0)){
		strcpy(group_name_list+(MAX_GROUP_NAME_LIST-5),"...");
		group_names_len=MAX_GROUP_NAME_LIST-1;
	} else {
		group_names_len+=str_len;
		group_name_list[group_names_len++]=' ';
	}
	group_name_list[group_names_len]=0;

	offset = dissect_rpc_string(tvb, pinfo, tree, 
			hf_mount_groups_group, offset, NULL);

	return offset;
}


/* RFC 1094, Page 26 */
/* RFC 1813, Page 113 */
static int
dissect_exportlist(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item* exportlist_item = NULL;
	proto_tree* exportlist_tree = NULL;
	int old_offset = offset;
	int groups_offset;
	proto_item* groups_item = NULL;
	proto_item* groups_tree = NULL;
	char* directory;

	group_name_list[0]=0;
	group_names_len=0;
	if (tree) {
		exportlist_item = proto_tree_add_item(tree, hf_mount_exportlist, tvb,
					offset, -1, FALSE);
		if (exportlist_item)
			exportlist_tree = proto_item_add_subtree(exportlist_item, ett_mount_exportlist);
	}

	offset = dissect_rpc_string(tvb, pinfo, exportlist_tree,
			hf_mount_exportlist_directory, offset, &directory);
	groups_offset = offset;

	if (tree) {
		groups_item = proto_tree_add_item(exportlist_tree, hf_mount_groups, tvb,
					offset, -1, FALSE);
		if (groups_item)
			groups_tree = proto_item_add_subtree(groups_item, ett_mount_groups);
	}

	offset = dissect_rpc_list(tvb, pinfo, groups_tree, offset, dissect_group);
	if (groups_item) {
		/* mark empty lists */
		if (offset - groups_offset == 4) {
			proto_item_set_text(groups_item, "Groups: empty");
		}

		/* now we know, that groups is shorter */
		proto_item_set_len(groups_item, offset - groups_offset);
	}

	if (exportlist_item) {
		/* now we have a nicer string */
		proto_item_set_text(exportlist_item, "Export List Entry: %s -> %s", directory,group_name_list);
		/* now we know, that exportlist is shorter */
		proto_item_set_len(exportlist_item, offset - old_offset);
	}
	g_free(directory);

	return offset;
}


/* RFC 1094, Page 26 */
/* RFC 1813, Page 113 */
static int
dissect_mount_export_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset = dissect_rpc_list(tvb, pinfo, tree, offset, dissect_exportlist);

	return offset;
}


#define	OFFS_MASK	32	/* offset of the "pc_mask" field */

#define	PC_ERROR_ALL		0x0001
#define	PC_ERROR_LINK_MAX	0x0002
#define	PC_ERROR_MAX_CANON	0x0004
#define	PC_ERROR_MAX_INPUT	0x0008
#define	PC_ERROR_NAME_MAX	0x0010
#define	PC_ERROR_PATH_MAX	0x0020
#define	PC_ERROR_PIPE_BUF	0x0040
#define	PC_CHOWN_RESTRICTED	0x0080
#define	PC_NO_TRUNC		0x0100
#define	PC_ERROR_VDISABLE	0x0200

static const true_false_string tos_error_all = {
  "All info invalid",
  "Some or all info valid"
};

static const true_false_string tos_error_link_max = {
  "LINK_MAX invalid",
  "LINK_MAX valid"
};

static const true_false_string tos_error_max_canon = {
  "MAX_CANON invalid",
  "MAX_CANON valid"
};

static const true_false_string tos_error_max_input = {
  "MAX_INPUT invalid",
  "MAX_INPUT valid"
};

static const true_false_string tos_error_name_max = {
  "NAME_MAX invalid",
  "NAME_MAX valid"
};

static const true_false_string tos_error_path_max = {
  "PATH_MAX invalid",
  "PATH_MAX valid"
};

static const true_false_string tos_error_pipe_buf = {
  "PIPE_BUF invalid",
  "PIPE_BUF valid"
};

static const true_false_string tos_chown_restricted = {
  "Only a privileged user can change the ownership of a file",
  "Users may give away their own files"
};

static const true_false_string tos_no_trunc = {
  "File names that are too long will get an error",
  "File names that are too long will be truncated"
};

static const true_false_string tos_error_vdisable = {
  "VDISABLE invalid",
  "VDISABLE valid"
};


static int
dissect_mount_pathconf_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	int saved_offset;
	guint32 pc_mask;
	proto_item *lock_item;
	proto_tree *lock_tree;

	saved_offset=offset;
	/*
	 * Extract the mask first, so we know which other fields the
	 * server was able to return to us.
	 */
	pc_mask = tvb_get_ntohl(tvb, offset+OFFS_MASK) & 0xffff;
	if (!(pc_mask & (PC_ERROR_LINK_MAX|PC_ERROR_ALL))) {
		if (tree) {
			dissect_rpc_uint32(tvb,pinfo,tree,hf_mount_pathconf_link_max,offset);
		}
	}
	offset += 4;

	if (!(pc_mask & (PC_ERROR_MAX_CANON|PC_ERROR_ALL))) {
		if (tree) {
			proto_tree_add_item(tree, 
				hf_mount_pathconf_max_canon,tvb,offset+2,2,
				tvb_get_ntohs(tvb,offset)&0xffff);
		}
	}
	offset += 4;

	if (!(pc_mask & (PC_ERROR_MAX_INPUT|PC_ERROR_ALL))) {
		if (tree) {
			proto_tree_add_item(tree, 
				hf_mount_pathconf_max_input,tvb,offset+2,2,
				tvb_get_ntohs(tvb,offset)&0xffff);
		}
	}
	offset += 4;

	if (!(pc_mask & (PC_ERROR_NAME_MAX|PC_ERROR_ALL))) {
		if (tree) {
			proto_tree_add_item(tree, 
				hf_mount_pathconf_name_max,tvb,offset+2,2,
				tvb_get_ntohs(tvb,offset)&0xffff);
		}
	}
	offset += 4;

	if (!(pc_mask & (PC_ERROR_PATH_MAX|PC_ERROR_ALL))) {
		if (tree) {
			proto_tree_add_item(tree, 
				hf_mount_pathconf_path_max,tvb,offset+2,2,
				tvb_get_ntohs(tvb,offset)&0xffff);
		}
	}
	offset += 4;

	if (!(pc_mask & (PC_ERROR_PIPE_BUF|PC_ERROR_ALL))) {
		if (tree) {
			proto_tree_add_item(tree, 
				hf_mount_pathconf_pipe_buf,tvb,offset+2,2,
				tvb_get_ntohs(tvb,offset)&0xffff);
		}
	}
	offset += 4;

	offset += 4;	/* skip "pc_xxx" pad field */

	if (!(pc_mask & (PC_ERROR_VDISABLE|PC_ERROR_ALL))) {
		if (tree) {
			proto_tree_add_item(tree, 
				hf_mount_pathconf_vdisable,tvb,offset+3,1,
				tvb_get_ntohs(tvb,offset)&0xffff);
		}
	}
	offset += 4;


	if (tree) {
		lock_item = proto_tree_add_item(tree, hf_mount_pathconf_mask, tvb,
					offset+2, 2, FALSE);

		lock_tree = proto_item_add_subtree(lock_item, ett_mount_pathconf_mask);
		proto_tree_add_boolean(lock_tree, hf_mount_pathconf_error_all, tvb,
		    offset + 2, 2, pc_mask);

		proto_tree_add_boolean(lock_tree, hf_mount_pathconf_error_link_max, tvb,
		    offset + 2, 2, pc_mask);
		proto_tree_add_boolean(lock_tree, hf_mount_pathconf_error_max_canon, tvb,
		    offset + 2, 2, pc_mask);
		proto_tree_add_boolean(lock_tree, hf_mount_pathconf_error_max_input, tvb,
		    offset + 2, 2, pc_mask);
		proto_tree_add_boolean(lock_tree, hf_mount_pathconf_error_name_max, tvb,
		    offset + 2, 2, pc_mask);
		proto_tree_add_boolean(lock_tree, hf_mount_pathconf_error_path_max, tvb,
		    offset + 2, 2, pc_mask);
		proto_tree_add_boolean(lock_tree, hf_mount_pathconf_error_pipe_buf, tvb,
		    offset + 2, 2, pc_mask);
		proto_tree_add_boolean(lock_tree, hf_mount_pathconf_chown_restricted, tvb,
		    offset + 2, 2, pc_mask);
		proto_tree_add_boolean(lock_tree, hf_mount_pathconf_no_trunc, tvb,
		    offset + 2, 2, pc_mask);
		proto_tree_add_boolean(lock_tree, hf_mount_pathconf_error_vdisable, tvb,
		    offset + 2, 2, pc_mask);
	}

	offset += 8;
	return offset;
}

/* RFC 1813, Page 107 */
static const value_string mount3_mountstat3[] = 
{
	{	0,	"OK" },
	{	1,	"ERR_PERM" },
	{	2,	"ERR_NOENT" },
	{	5,	"ERR_IO" },
	{	13,	"ERR_ACCESS" },
	{	20,	"ERR_NOTDIR" },
	{	22,	"ERR_INVAL" },
	{	63,	"ERR_NAMETOOLONG" },
	{	10004,	"ERR_NOTSUPP" },
	{	10006,	"ERR_SERVERFAULT" },
	{	0,	NULL }
};


/* RFC 1813, Page 107 */
static int
dissect_mountstat3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hfindex, guint32 *status)
{
	guint32 mountstat3;

	mountstat3 = tvb_get_ntohl(tvb, offset);

	offset = dissect_rpc_uint32(tvb,pinfo,tree,hfindex,offset);
	*status = mountstat3;
	return offset;
}

/* RFC 1831, Page 109 */
static int
dissect_mount3_mnt_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint32 status;
	guint32 auth_flavors;
	guint32 auth_flavor;
	guint32 auth_flavor_i;
	
	offset = dissect_mountstat3(tvb,pinfo,tree,offset,hf_mount3_status,&status);

	switch (status) {
		case 0:
			offset = dissect_nfs_fh3(tvb,offset,pinfo,tree,"fhandle");

			auth_flavors = tvb_get_ntohl(tvb, offset);
			proto_tree_add_uint(tree,hf_mount_flavors, tvb,
				offset, 4, auth_flavors);
			offset += 4;
			for (auth_flavor_i = 0 ; auth_flavor_i < auth_flavors ; auth_flavor_i++) {
				auth_flavor = tvb_get_ntohl(tvb, offset);
				proto_tree_add_uint(tree,hf_mount_flavor, tvb,
					offset, 4, auth_flavor);
				offset += 4;
			}
		break;
		default:
			/* void */
		break;
	}
	
	return offset;
}


/* proc number, "proc name", dissect_request, dissect_reply */
/* NULL as function pointer means: type of arguments is "void". */

/* Mount protocol version 1, RFC 1094 */
static const vsff mount1_proc[] = {
    { 0, "NULL", NULL, NULL },
    { MOUNTPROC_MNT,        "MNT",      
		dissect_mount_dirpath_call, dissect_mount1_mnt_reply },
    { MOUNTPROC_DUMP,       "DUMP",
		NULL, dissect_mount_dump_reply },
    { MOUNTPROC_UMNT,      "UMNT",        
		dissect_mount_dirpath_call, NULL },
    { MOUNTPROC_UMNTALL,   "UMNTALL",
		NULL, NULL },
    { MOUNTPROC_EXPORT,    "EXPORT",
		NULL, dissect_mount_export_reply },
    { MOUNTPROC_EXPORTALL, "EXPORTALL",
		NULL, dissect_mount_export_reply },
    { 0, NULL, NULL, NULL }
};
/* end of mount version 1 */


/* Mount protocol version 2, private communication from somebody at Sun;
   mount V2 is V1 plus MOUNTPROC_PATHCONF to fetch information for the
   POSIX "pathconf()" call. */
static const vsff mount2_proc[] = {
    { 0, "NULL", NULL, NULL },
    { MOUNTPROC_MNT,        "MNT",      
		dissect_mount_dirpath_call, dissect_mount1_mnt_reply },
    { MOUNTPROC_DUMP,       "DUMP",
		NULL, dissect_mount_dump_reply },
    { MOUNTPROC_UMNT,      "UMNT",        
		dissect_mount_dirpath_call, NULL },
    { MOUNTPROC_UMNTALL,   "UMNTALL",
		NULL, NULL },
    { MOUNTPROC_EXPORT,    "EXPORT",
		NULL, dissect_mount_export_reply },
    { MOUNTPROC_EXPORTALL, "EXPORTALL",
		NULL, dissect_mount_export_reply },
    { MOUNTPROC_PATHCONF,  "PATHCONF",
		dissect_mount_dirpath_call, dissect_mount_pathconf_reply },
    { 0, NULL, NULL, NULL }
};
/* end of mount version 2 */


/* Mount protocol version 3, RFC 1813 */
static const vsff mount3_proc[] = {
	{ 0, "NULL", NULL, NULL },
	{ MOUNTPROC_MNT, "MNT",
		dissect_mount_dirpath_call, dissect_mount3_mnt_reply },
	{ MOUNTPROC_DUMP, "DUMP",
		NULL, dissect_mount_dump_reply },
	{ MOUNTPROC_UMNT, "UMNT",
		dissect_mount_dirpath_call, NULL },
	{ MOUNTPROC_UMNTALL, "UMNTALL",
		NULL, NULL },
	{ MOUNTPROC_EXPORT, "EXPORT",
		NULL, dissect_mount_export_reply },
	{ 0, NULL, NULL, NULL }
};
/* end of Mount protocol version 3 */


void
proto_register_mount(void)
{
	static hf_register_info hf[] = {
		{ &hf_mount_path, {
			"Path", "mount.path", FT_STRING, BASE_DEC,
			NULL, 0, "Path", HFILL }},
		{ &hf_mount3_status, {
			"Status", "mount.status", FT_UINT32, BASE_DEC,
			VALS(mount3_mountstat3), 0, "Status", HFILL }},
		{ &hf_mount_mountlist_hostname, {
			"Hostname", "mount.dump.hostname", FT_STRING, BASE_DEC,
			NULL, 0, "Hostname", HFILL }},
		{ &hf_mount_mountlist_directory, {
			"Directory", "mount.dump.directory", FT_STRING, BASE_DEC,
			NULL, 0, "Directory", HFILL }},
		{ &hf_mount_mountlist, {
			"Mount List Entry", "mount.dump.entry", FT_NONE, 0,
			NULL, 0, "Mount List Entry", HFILL }},
		{ &hf_mount_groups_group, {
			"Group", "mount.export.group", FT_STRING, BASE_DEC,
			NULL, 0, "Group", HFILL }},
		{ &hf_mount_groups, {
			"Groups", "mount.export.groups", FT_NONE, 0,
			NULL, 0, "Groups", HFILL }},
		{ &hf_mount_exportlist_directory, {
			"Directory", "mount.export.directory", FT_STRING, BASE_DEC,
			NULL, 0, "Directory", HFILL }},
		{ &hf_mount_exportlist, {
			"Export List Entry", "mount.export.entry", FT_NONE, 0,
			NULL, 0, "Export List Entry", HFILL }},
		{ &hf_mount_pathconf_link_max, {
			"Maximum number of links to a file", "mount.pathconf.link_max",
			FT_UINT32, BASE_DEC,
			NULL, 0, "Maximum number of links allowed to a file", HFILL }},
		{ &hf_mount_pathconf_max_canon, {
			"Maximum terminal input line length", "mount.pathconf.max_canon",
			FT_UINT16, BASE_DEC,
			NULL, 0, "Max tty input line length", HFILL }},
		{ &hf_mount_pathconf_max_input, {
			"Terminal input buffer size", "mount.pathconf.max_input",
			FT_UINT16, BASE_DEC,
			NULL, 0, "Terminal input buffer size", HFILL }},
		{ &hf_mount_pathconf_name_max, {
			"Maximum file name length", "mount.pathconf.name_max",
			FT_UINT16, BASE_DEC,
			NULL, 0, "Maximum file name length", HFILL }},
		{ &hf_mount_pathconf_path_max, {
			"Maximum path name length", "mount.pathconf.path_max",
			FT_UINT16, BASE_DEC,
			NULL, 0, "Maximum path name length", HFILL }},
		{ &hf_mount_pathconf_pipe_buf, {
			"Pipe buffer size", "mount.pathconf.pipe_buf",
			FT_UINT16, BASE_DEC,
			NULL, 0, "Maximum amount of data that can be written atomically to a pipe", HFILL }},
		{ &hf_mount_pathconf_vdisable, {
			"VDISABLE character", "mount.pathconf.vdisable_char",
			FT_UINT8, BASE_HEX,
			NULL, 0, "Character value to disable a terminal special character", HFILL }},
		{ &hf_mount_pathconf_mask, {
			"Reply error/status bits", "mount.pathconf.mask",
			FT_UINT16, BASE_HEX,
			NULL, 0, "Bit mask with error and status bits", HFILL }},
		{ &hf_mount_pathconf_error_all, {
			"ERROR_ALL",	"mount.pathconf.mask.error_all",
			FT_BOOLEAN, 16, TFS(&tos_error_all),
			PC_ERROR_ALL, "", HFILL }},
		{ &hf_mount_pathconf_error_link_max, {
			"ERROR_LINK_MAX", "mount.pathconf.mask.error_link_max",
			FT_BOOLEAN, 16, TFS(&tos_error_link_max),
			PC_ERROR_LINK_MAX, "", HFILL }},
		{ &hf_mount_pathconf_error_max_canon, {
			"ERROR_MAX_CANON", "mount.pathconf.mask.error_max_canon",
			FT_BOOLEAN, 16, TFS(&tos_error_max_canon),
			PC_ERROR_MAX_CANON, "", HFILL }},
		{ &hf_mount_pathconf_error_max_input, {
			"ERROR_MAX_INPUT", "mount.pathconf.mask.error_max_input",
			FT_BOOLEAN, 16, TFS(&tos_error_max_input),
			PC_ERROR_MAX_INPUT, "", HFILL }},
		{ &hf_mount_pathconf_error_name_max, {
			"ERROR_NAME_MAX", "mount.pathconf.mask.error_name_max",
			FT_BOOLEAN, 16, TFS(&tos_error_name_max),
			PC_ERROR_NAME_MAX, "", HFILL }},
		{ &hf_mount_pathconf_error_path_max, {
			"ERROR_PATH_MAX", "mount.pathconf.mask.error_path_max",
			FT_BOOLEAN, 16, TFS(&tos_error_path_max),
			PC_ERROR_PATH_MAX, "", HFILL }},
		{ &hf_mount_pathconf_error_pipe_buf, {
			"ERROR_PIPE_BUF", "mount.pathconf.mask.error_pipe_buf",
			FT_BOOLEAN, 16, TFS(&tos_error_pipe_buf),
			PC_ERROR_PIPE_BUF, "", HFILL }},
		{ &hf_mount_pathconf_chown_restricted, {
			"CHOWN_RESTRICTED", "mount.pathconf.mask.chown_restricted",
			FT_BOOLEAN, 16, TFS(&tos_chown_restricted),
			PC_CHOWN_RESTRICTED, "", HFILL }},
		{ &hf_mount_pathconf_no_trunc, {
			"NO_TRUNC", "mount.pathconf.mask.no_trunc",
			FT_BOOLEAN, 16, TFS(&tos_no_trunc),
			PC_NO_TRUNC, "", HFILL }},
		{ &hf_mount_pathconf_error_vdisable, {
			"ERROR_VDISABLE", "mount.pathconf.mask.error_vdisable",
			FT_BOOLEAN, 16, TFS(&tos_error_vdisable),
			PC_ERROR_VDISABLE, "", HFILL }},
		{ &hf_mount_flavors, {
			"Flavors", "mount.flavors", FT_UINT32, BASE_DEC,
			NULL, 0, "Flavors", HFILL }},
		{ &hf_mount_flavor, {
			"Flavor", "mount.flavor", FT_UINT32, BASE_DEC,
			VALS(rpc_auth_flavor), 0, "Flavor", HFILL }},
	};
	static gint *ett[] = {
		&ett_mount,
		&ett_mount_mountlist,
		&ett_mount_groups,
		&ett_mount_exportlist,
		&ett_mount_pathconf_mask,
	};

	proto_mount = proto_register_protocol("Mount Service", "MOUNT", "mount");
	proto_register_field_array(proto_mount, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_mount(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_mount, MOUNT_PROGRAM, ett_mount);
	/* Register the procedure tables */
	rpc_init_proc_table(MOUNT_PROGRAM, 1, mount1_proc);
	rpc_init_proc_table(MOUNT_PROGRAM, 2, mount2_proc);
	rpc_init_proc_table(MOUNT_PROGRAM, 3, mount3_proc);
}
