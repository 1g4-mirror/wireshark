/* plugin_table.h
 * Table of exported addresses for Ethereal plugins.
 *
 * $Id: plugin_table.h,v 1.38 2002/02/02 03:42:18 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * Copyright 2000 by Gilbert Ramirez <gram@alumni.rice.edu>
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

#ifndef PLUGIN_TABLE_H
#define PLUGIN_TABLE_H

#ifdef PLUGINS_NEED_ADDRESS_TABLE

/* Some OSes (Win32) have DLLs that cannot reference symbols in the parent
   executable, so the executable needs to provide a collection of pointers
   to those functions for the DLL plugin to use. */

/* Typedefs to make our plugin_address_table_t struct look prettier */
typedef gint (*addr_check_col)(column_info*, gint);
typedef void (*addr_col_clear)(column_info*, gint);
typedef void (*addr_col_add_fstr)(column_info*, gint, gchar*, ...);
typedef void (*addr_col_append_fstr)(column_info*, gint, gchar*, ...);
typedef void (*addr_col_prepend_fstr)(column_info*, gint, gchar*, ...);
typedef void (*addr_col_add_str)(column_info*, gint, const gchar*);
typedef void (*addr_col_append_str)(column_info*, gint, gchar*);
typedef void (*addr_col_set_str)(column_info*, gint, gchar*);

typedef void (*addr_register_init_routine)(void (*func)(void));
typedef void (*addr_register_postseq_cleanup_routine)(void (*func)(void));
typedef conversation_t *(*addr_conversation_new)(address *, address *, 
    port_type, guint32, guint32, guint);
typedef conversation_t *(*addr_find_conversation)(address *, address *, 
    port_type, guint32, guint32, guint);
typedef gchar* (*addr_match_strval)(guint32, const value_string*);
typedef gchar* (*addr_val_to_str)(guint32, const value_string *, const char *);

typedef int (*addr_proto_register_protocol)(char*, char*, char*);
typedef void (*addr_proto_register_field_array)(int, hf_register_info*, int);
typedef void (*addr_proto_register_subtree_array)(int**, int);

typedef void (*addr_dissector_add)(const char *, guint32, dissector_handle_t);
typedef void (*addr_dissector_delete)(const char *, guint32,
    dissector_handle_t);
typedef void (*addr_dissector_add_handle)(const char *,
    dissector_handle_t);

typedef void (*addr_heur_dissector_add)(const char *, heur_dissector_t, int);

typedef void (*addr_register_dissector)(const char *, dissector_t, int);
typedef dissector_handle_t (*addr_find_dissector)(const char *);
typedef dissector_handle_t (*addr_create_dissector_handle)(dissector_t dissector,
    int proto);
typedef void (*addr_call_dissector)(dissector_handle_t, tvbuff_t *,
    packet_info *, proto_tree *);

typedef void (*addr_dissect_data)(tvbuff_t *, int, packet_info *, proto_tree *);

typedef gboolean (*addr_proto_is_protocol_enabled)(int);

typedef int (*addr_proto_item_get_len)(proto_item*);
typedef void (*addr_proto_item_set_len)(proto_item*, gint);
typedef void (*addr_proto_item_set_text)(proto_item*, const char*, ...);
typedef void (*addr_proto_item_append_text)(proto_item*, const char*, ...);
typedef proto_tree* (*addr_proto_item_add_subtree)(proto_item*, gint);
typedef proto_item* (*addr_proto_tree_add_item)(proto_tree*, int, tvbuff_t*, gint, gint, gboolean);
typedef proto_item* (*addr_proto_tree_add_item_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, gboolean);
typedef proto_item* (*addr_proto_tree_add_protocol_format)(proto_tree*, int, tvbuff_t*, gint, gint, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_bytes)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*);
typedef proto_item* (*addr_proto_tree_add_bytes_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*);
typedef proto_item* (*addr_proto_tree_add_bytes_format)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_time)(proto_tree*, int, tvbuff_t*, gint, gint, nstime_t*);
typedef proto_item* (*addr_proto_tree_add_time_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, nstime_t*);
typedef proto_item* (*addr_proto_tree_add_time_format)(proto_tree*, int, tvbuff_t*, gint, gint, nstime_t*, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_ipxnet)(proto_tree*, int, tvbuff_t*, gint, gint, guint32);
typedef proto_item* (*addr_proto_tree_add_ipxnet_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, guint32);
typedef proto_item* (*addr_proto_tree_add_ipxnet_format)(proto_tree*, int, tvbuff_t*, gint, gint, guint32, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_ipv4)(proto_tree*, int, tvbuff_t*, gint, gint, guint32);
typedef proto_item* (*addr_proto_tree_add_ipv4_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, guint32);
typedef proto_item* (*addr_proto_tree_add_ipv4_format)(proto_tree*, int, tvbuff_t*, gint, gint, guint32, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_ipv6)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*);
typedef proto_item* (*addr_proto_tree_add_ipv6_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*);
typedef proto_item* (*addr_proto_tree_add_ipv6_format)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_ether)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*);
typedef proto_item* (*addr_proto_tree_add_ether_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*);
typedef proto_item* (*addr_proto_tree_add_ether_format)(proto_tree*, int, tvbuff_t*, gint, gint, const guint8*, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_string)(proto_tree*, int, tvbuff_t*, gint, gint, const char*);
typedef proto_item* (*addr_proto_tree_add_string_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, const char*);
typedef proto_item* (*addr_proto_tree_add_string_format)(proto_tree*, int, tvbuff_t*, gint, gint, const char*, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_boolean)(proto_tree*, int, tvbuff_t*, gint, gint, guint32);
typedef proto_item* (*addr_proto_tree_add_boolean_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, guint32);
typedef proto_item* (*addr_proto_tree_add_boolean_format)(proto_tree*, int, tvbuff_t*, gint, gint, guint32, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_double)(proto_tree*, int, tvbuff_t*, gint, gint, double);
typedef proto_item* (*addr_proto_tree_add_double_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, double);
typedef proto_item* (*addr_proto_tree_add_double_format)(proto_tree*, int, tvbuff_t*, gint, gint, double, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_uint)(proto_tree*, int, tvbuff_t*, gint, gint, guint32);
typedef proto_item* (*addr_proto_tree_add_uint_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, guint32);
typedef proto_item* (*addr_proto_tree_add_uint_format)(proto_tree*, int, tvbuff_t*, gint, gint, guint32, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_int)(proto_tree*, int, tvbuff_t*, gint, gint, gint32);
typedef proto_item* (*addr_proto_tree_add_int_hidden)(proto_tree*, int, tvbuff_t*, gint, gint, gint32);
typedef proto_item* (*addr_proto_tree_add_int_format)(proto_tree*, int, tvbuff_t*, gint, gint, gint32, const char*, ...);

typedef proto_item* (*addr_proto_tree_add_text)(proto_tree*, tvbuff_t*, gint, gint, const char*, ...);

typedef tvbuff_t* (*addr_tvb_new_subset)(tvbuff_t*, gint, gint, gint);

typedef void (*addr_tvb_set_free_cb)(tvbuff_t*, tvbuff_free_cb_t);
typedef void (*addr_tvb_set_child_real_data_tvbuff)(tvbuff_t*, tvbuff_t*);
typedef tvbuff_t* (*addr_tvb_new_real_data)(const guint8*, guint, gint, const gchar*);

typedef guint (*addr_tvb_length)(tvbuff_t*);
typedef gint (*addr_tvb_length_remaining)(tvbuff_t*, gint);
typedef gboolean (*addr_tvb_bytes_exist)(tvbuff_t*, gint, gint);
typedef gboolean (*addr_tvb_offset_exists)(tvbuff_t*, gint);
typedef guint (*addr_tvb_reported_length)(tvbuff_t*);
typedef gint (*addr_tvb_reported_length_remaining)(tvbuff_t*, gint);

typedef guint8 (*addr_tvb_get_guint8)(tvbuff_t*, gint);

typedef guint16 (*addr_tvb_get_ntohs)(tvbuff_t*, gint);
typedef guint32 (*addr_tvb_get_ntoh24)(tvbuff_t*, gint);
typedef guint32 (*addr_tvb_get_ntohl)(tvbuff_t*, gint);

typedef guint16 (*addr_tvb_get_letohs)(tvbuff_t*, gint);
typedef guint32 (*addr_tvb_get_letoh24)(tvbuff_t*, gint);
typedef guint32 (*addr_tvb_get_letohl)(tvbuff_t*, gint);

typedef guint8* (*addr_tvb_memcpy)(tvbuff_t*, guint8* target, gint, gint);
typedef guint8* (*addr_tvb_memdup)(tvbuff_t*, gint, gint);

typedef const guint8* (*addr_tvb_get_ptr)(tvbuff_t*, gint, gint);

typedef gint (*addr_tvb_find_guint8)(tvbuff_t*, gint, gint, guint8);
typedef gint (*addr_tvb_pbrk_guint8)(tvbuff_t *, gint, gint, guint8 *);

typedef gint (*addr_tvb_strnlen)(tvbuff_t*, gint, guint);

typedef guint8 * (*addr_tvb_format_text)(tvbuff_t*, gint, gint);

typedef gint (*addr_tvb_get_nstringz)(tvbuff_t*, gint, guint, guint8*);
typedef gint (*addr_tvb_get_nstringz0)(tvbuff_t*, gint, guint, guint8*);

typedef gint (*addr_tvb_find_line_end)(tvbuff_t*, gint, int, gint *);
typedef gint (*addr_tvb_find_line_end_unquoted)(tvbuff_t*, gint, int, gint *);

typedef gint (*addr_tvb_strneql)(tvbuff_t*, gint, const guint8 *, gint);
typedef gint (*addr_tvb_strncaseeql)(tvbuff_t*, gint, const guint8 *, gint);

typedef gchar *(*addr_tvb_bytes_to_str)(tvbuff_t*, gint, gint len);

typedef struct pref_module *(*addr_prefs_register_protocol)(int,
    void (*)(void));
typedef void (*addr_prefs_register_uint_preference)(struct pref_module *,
    const char *, const char *, const char *, guint, guint *);
typedef void (*addr_prefs_register_bool_preference)(struct pref_module *,
    const char *, const char *, const char *, gboolean *);
typedef void (*addr_prefs_register_enum_preference)(struct pref_module *,
    const char *, const char *, const char *, gint *, const enum_val_t *,
    gboolean);
typedef void (*addr_prefs_register_string_preference)(struct pref_module *,
    const char *, const char *, const char *, char**);

typedef void (*addr_register_giop_user)(giop_sub_dissector_t *, gchar *, int);
typedef gboolean (*addr_is_big_endian)(MessageHeader *);
typedef guint32 (*addr_get_CDR_encap_info)(tvbuff_t *, proto_tree *, gint *,
		gboolean, guint32, gboolean *, guint32 *);
typedef void (*addr_get_CDR_any)(tvbuff_t *, proto_tree *, gint *,
		gboolean, int, MessageHeader *);
typedef gboolean (*addr_get_CDR_boolean)(tvbuff_t *, int *);
typedef guint8 (*addr_get_CDR_char)(tvbuff_t *, int *);
typedef gdouble (*addr_get_CDR_double)(tvbuff_t *, int *, gboolean, int);
typedef guint32 (*addr_get_CDR_enum)(tvbuff_t *, int *, gboolean, int);
typedef void (*addr_get_CDR_fixed)(tvbuff_t *, gchar **, gint *, guint32,
		gint32);
typedef gfloat (*addr_get_CDR_float)(tvbuff_t *, int *, gboolean, int);
typedef void (*addr_get_CDR_interface)(tvbuff_t *, packet_info *, proto_tree *,
		int *, gboolean, int);
typedef gint32 (*addr_get_CDR_long)(tvbuff_t *, int *, gboolean, int);
typedef void (*addr_get_CDR_object)(tvbuff_t *, packet_info *, proto_tree *,
		int *, gboolean, int);
typedef guint8 (*addr_get_CDR_octet)(tvbuff_t *, int *);
typedef void (*addr_get_CDR_octet_seq)(tvbuff_t *, gchar **, int *, int);
typedef gint16 (*addr_get_CDR_short)(tvbuff_t *, int *, gboolean, int);
typedef guint32 (*addr_get_CDR_string)(tvbuff_t *, gchar **, int *, gboolean,
		int);
typedef guint32 (*addr_get_CDR_typeCode)(tvbuff_t *, proto_tree *, gint *,
	gboolean, int, MessageHeader *);
typedef guint32 (*addr_get_CDR_ulong)(tvbuff_t *, int *, gboolean, int);
typedef guint16 (*addr_get_CDR_ushort)(tvbuff_t *, int *, gboolean, int);
typedef gint8 (*addr_get_CDR_wchar)(tvbuff_t *, gchar **, int *,
		MessageHeader *);
typedef guint32 (*addr_get_CDR_wstring)(tvbuff_t *, gchar **, int *, gboolean,
		int, MessageHeader *);

typedef struct  {

	addr_check_col				p_check_col;
	addr_col_clear				p_col_clear;
	addr_col_add_fstr			p_col_add_fstr;
	addr_col_append_fstr			p_col_append_fstr;
	addr_col_prepend_fstr			p_col_prepend_fstr;
	addr_col_add_str			p_col_add_str;
	addr_col_append_str			p_col_append_str;
	addr_col_set_str			p_col_set_str;

	addr_register_init_routine		p_register_init_routine;
	addr_register_postseq_cleanup_routine	p_register_postseq_cleanup_routine;
	addr_conversation_new			p_conversation_new;
	addr_find_conversation			p_find_conversation;
	addr_match_strval			p_match_strval;
	addr_val_to_str				p_val_to_str;

	addr_proto_register_protocol		p_proto_register_protocol;
	addr_proto_register_field_array		p_proto_register_field_array;
	addr_proto_register_subtree_array	p_proto_register_subtree_array;

	addr_dissector_add			p_dissector_add;
	addr_dissector_delete			p_dissector_delete;
	addr_dissector_add_handle		p_dissector_add_handle;

	addr_heur_dissector_add			p_heur_dissector_add;

	addr_register_dissector			p_register_dissector;
	addr_find_dissector			p_find_dissector;
	addr_create_dissector_handle		p_create_dissector_handle;
	addr_call_dissector			p_call_dissector;

	addr_dissect_data			p_dissect_data;

	addr_proto_is_protocol_enabled		p_proto_is_protocol_enabled;

	addr_proto_item_get_len			p_proto_item_get_len;
	addr_proto_item_set_len			p_proto_item_set_len;
	addr_proto_item_set_text		p_proto_item_set_text;
	addr_proto_item_append_text		p_proto_item_append_text;
	addr_proto_item_add_subtree		p_proto_item_add_subtree;
	addr_proto_tree_add_item		p_proto_tree_add_item;
	addr_proto_tree_add_item_hidden		p_proto_tree_add_item_hidden;
	addr_proto_tree_add_protocol_format	p_proto_tree_add_protocol_format;
	addr_proto_tree_add_bytes		p_proto_tree_add_bytes;
	addr_proto_tree_add_bytes_hidden	p_proto_tree_add_bytes_hidden;
	addr_proto_tree_add_bytes_format	p_proto_tree_add_bytes_format;
	addr_proto_tree_add_time		p_proto_tree_add_time;
	addr_proto_tree_add_time_hidden		p_proto_tree_add_time_hidden;
	addr_proto_tree_add_time_format		p_proto_tree_add_time_format;
	addr_proto_tree_add_ipxnet		p_proto_tree_add_ipxnet;
	addr_proto_tree_add_ipxnet_hidden	p_proto_tree_add_ipxnet_hidden;
	addr_proto_tree_add_ipxnet_format	p_proto_tree_add_ipxnet_format;
	addr_proto_tree_add_ipv4		p_proto_tree_add_ipv4;
	addr_proto_tree_add_ipv4_hidden		p_proto_tree_add_ipv4_hidden;
	addr_proto_tree_add_ipv4_format		p_proto_tree_add_ipv4_format;
	addr_proto_tree_add_ipv6		p_proto_tree_add_ipv6;
	addr_proto_tree_add_ipv6_hidden		p_proto_tree_add_ipv6_hidden;
	addr_proto_tree_add_ipv6_format		p_proto_tree_add_ipv6_format;
	addr_proto_tree_add_ether		p_proto_tree_add_ether;
	addr_proto_tree_add_ether_hidden	p_proto_tree_add_ether_hidden;
	addr_proto_tree_add_ether_format	p_proto_tree_add_ether_format;
	addr_proto_tree_add_string		p_proto_tree_add_string;
	addr_proto_tree_add_string_hidden	p_proto_tree_add_string_hidden;
	addr_proto_tree_add_string_format	p_proto_tree_add_string_format;
	addr_proto_tree_add_boolean		p_proto_tree_add_boolean;
	addr_proto_tree_add_boolean_hidden	p_proto_tree_add_boolean_hidden;
	addr_proto_tree_add_boolean_format	p_proto_tree_add_boolean_format;
	addr_proto_tree_add_double		p_proto_tree_add_double;
	addr_proto_tree_add_double_hidden	p_proto_tree_add_double_hidden;
	addr_proto_tree_add_double_format	p_proto_tree_add_double_format;
	addr_proto_tree_add_uint		p_proto_tree_add_uint;
	addr_proto_tree_add_uint_hidden		p_proto_tree_add_uint_hidden;
	addr_proto_tree_add_uint_format		p_proto_tree_add_uint_format;
	addr_proto_tree_add_int			p_proto_tree_add_int;
	addr_proto_tree_add_int_hidden		p_proto_tree_add_int_hidden;
	addr_proto_tree_add_int_format		p_proto_tree_add_int_format;
	addr_proto_tree_add_text		p_proto_tree_add_text;

	addr_tvb_new_subset			p_tvb_new_subset;

	addr_tvb_set_free_cb			p_tvb_set_free_cb;
	addr_tvb_set_child_real_data_tvbuff	p_tvb_set_child_real_data_tvbuff;
	addr_tvb_new_real_data			p_tvb_new_real_data;

	addr_tvb_length				p_tvb_length;
	addr_tvb_length_remaining		p_tvb_length_remaining;
	addr_tvb_bytes_exist			p_tvb_bytes_exist;
	addr_tvb_offset_exists			p_tvb_offset_exists;
	addr_tvb_reported_length		p_tvb_reported_length;
	addr_tvb_reported_length_remaining	p_tvb_reported_length_remaining;

	addr_tvb_get_guint8			p_tvb_get_guint8;

	addr_tvb_get_ntohs			p_tvb_get_ntohs;
	addr_tvb_get_ntoh24			p_tvb_get_ntoh24;
	addr_tvb_get_ntohl			p_tvb_get_ntohl;

	addr_tvb_get_letohs			p_tvb_get_letohs;
	addr_tvb_get_letoh24			p_tvb_get_letoh24;
	addr_tvb_get_letohl			p_tvb_get_letohl;

	addr_tvb_memcpy				p_tvb_memcpy;
	addr_tvb_memdup				p_tvb_memdup;

	addr_tvb_get_ptr			p_tvb_get_ptr;

	addr_tvb_find_guint8			p_tvb_find_guint8;
	addr_tvb_pbrk_guint8			p_tvb_pbrk_guint8;

	addr_tvb_strnlen			p_tvb_strnlen;

	addr_tvb_format_text			p_tvb_format_text;

	addr_tvb_get_nstringz			p_tvb_get_nstringz;
	addr_tvb_get_nstringz0			p_tvb_get_nstringz0;

	addr_tvb_find_line_end			p_tvb_find_line_end;
	addr_tvb_find_line_end_unquoted	p_tvb_find_line_end_unquoted;

	addr_tvb_strneql			p_tvb_strneql;
	addr_tvb_strncaseeql			p_tvb_strncaseeql;

	addr_tvb_bytes_to_str			p_tvb_bytes_to_str;

	addr_prefs_register_protocol		p_prefs_register_protocol;
	addr_prefs_register_uint_preference	p_prefs_register_uint_preference;
	addr_prefs_register_bool_preference	p_prefs_register_bool_preference;
	addr_prefs_register_enum_preference	p_prefs_register_enum_preference;
	addr_prefs_register_string_preference	p_prefs_register_string_preference;

        /* GIOP Begin */

	addr_register_giop_user			p_register_giop_user;
	addr_is_big_endian			p_is_big_endian;
        addr_get_CDR_encap_info                 p_get_CDR_encap_info;

	addr_get_CDR_any			p_get_CDR_any;
	addr_get_CDR_boolean			p_get_CDR_boolean;
	addr_get_CDR_char			p_get_CDR_char;
	addr_get_CDR_double			p_get_CDR_double;
	addr_get_CDR_enum			p_get_CDR_enum;
	addr_get_CDR_fixed			p_get_CDR_fixed;
	addr_get_CDR_float			p_get_CDR_float;
	addr_get_CDR_interface			p_get_CDR_interface;
	addr_get_CDR_long			p_get_CDR_long;
	addr_get_CDR_object			p_get_CDR_object;
	addr_get_CDR_octet			p_get_CDR_octet;
	addr_get_CDR_octet_seq			p_get_CDR_octet_seq;
	addr_get_CDR_short			p_get_CDR_short;
	addr_get_CDR_string			p_get_CDR_string;
	addr_get_CDR_typeCode			p_get_CDR_typeCode;
	addr_get_CDR_ulong			p_get_CDR_ulong;
	addr_get_CDR_ushort			p_get_CDR_ushort;
	addr_get_CDR_wchar			p_get_CDR_wchar;
	addr_get_CDR_wstring			p_get_CDR_wstring;

        /* GIOP End */


} plugin_address_table_t;

#else /* ! PLUGINS_NEED_ADDRESS_TABLE */

typedef void	plugin_address_table_t;

#endif /* PLUGINS_NEED_ADDRESS_TABLE */

#endif /* PLUGIN_TABLE_H */
