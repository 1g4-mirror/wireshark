/* plugin_api.h
 * Routines for Ethereal plugins.
 *
 * $Id: plugin_api.h,v 1.36 2002/02/02 03:42:18 guy Exp $
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

#ifndef PLUGIN_API_H
#define PLUGIN_API_H

#ifdef PLUGINS_NEED_ADDRESS_TABLE

/* Some OSes (Win32) have DLLs that cannot reference symbols in the parent
   executable, so the executable needs to provide a collection of pointers
   to global variables and functions for the DLL plugin to use. */

/* #defines for those functions that are called through pointers,
   and global variables that are referred to through pointers.

   #defined in this fashion so that the declaration of the functions
   and variables, from the system header files, turn into declarations
   of pointers to functions and variables, and the references to them in
   plugins, in the plugins, turn into references through the pointers. */
#define	check_col			(*p_check_col)
#define	col_clear			(*p_col_clear)
#define	col_add_fstr			(*p_col_add_fstr)
#define	col_append_fstr			(*p_col_append_fstr)
#define	col_prepend_fstr		(*p_col_prepend_fstr)
#define	col_add_str			(*p_col_add_str)
#define	col_append_str			(*p_col_append_str)
#define	col_set_str			(*p_col_set_str)

#define register_init_routine		(*p_register_init_routine)
#define register_postseq_cleanup_routine	(*p_register_postseq_cleanup_routine)
#define conversation_new		(*p_conversation_new)
#define find_conversation		(*p_find_conversation)
#define match_strval			(*p_match_strval)
#define val_to_str			(*p_val_to_str)

#define	proto_register_protocol		(*p_proto_register_protocol)
#define	proto_register_field_array	(*p_proto_register_field_array)
#define	proto_register_subtree_array	(*p_proto_register_subtree_array)

#define	dissector_add			(*p_dissector_add)
#define dissector_delete		(*p_dissector_delete)
#define	dissector_add_handle		(*p_dissector_add_handle)

#define	heur_dissector_add		(*p_heur_dissector_add)

#define register_dissector		(*p_register_dissector)
#define find_dissector			(*p_find_dissector)
#define create_dissector_handle		(*p_create_dissector_handle)
#define call_dissector			(*p_call_dissector)

#define proto_is_protocol_enabled	(*p_proto_is_protocol_enabled)

#define proto_item_get_len		(*p_proto_item_get_len)
#define proto_item_set_len		(*p_proto_item_set_len)
#define proto_item_set_text		(*p_proto_item_set_text)
#define proto_item_append_text		(*p_proto_item_append_text)
#define	proto_item_add_subtree		(*p_proto_item_add_subtree)
#define	proto_tree_add_item		(*p_proto_tree_add_item)
#define	proto_tree_add_item_hidden	(*p_proto_tree_add_item_hidden)
#define	proto_tree_add_protocol_format	(*p_proto_tree_add_protocol_format)
#define	proto_tree_add_bytes		(*p_proto_tree_add_bytes)
#define	proto_tree_add_bytes_hidden	(*p_proto_tree_add_bytes_hidden)
#define	proto_tree_add_bytes_format	(*p_proto_tree_add_bytes_format)
#define	proto_tree_add_time		(*p_proto_tree_add_time)
#define	proto_tree_add_time_hidden	(*p_proto_tree_add_time_hidden)
#define	proto_tree_add_time_format	(*p_proto_tree_add_time_format)
#define	proto_tree_add_ipxnet		(*p_proto_tree_add_ipxnet)
#define	proto_tree_add_ipxnet_hidden	(*p_proto_tree_add_ipxnet_hidden)
#define	proto_tree_add_ipxnet_format	(*p_proto_tree_add_ipxnet_format)
#define	proto_tree_add_ipv4		(*p_proto_tree_add_ipv4)
#define	proto_tree_add_ipv4_hidden	(*p_proto_tree_add_ipv4_hidden)
#define	proto_tree_add_ipv4_format	(*p_proto_tree_add_ipv4_format)
#define	proto_tree_add_ipv6		(*p_proto_tree_add_ipv6)
#define	proto_tree_add_ipv6_hidden	(*p_proto_tree_add_ipv6_hidden)
#define	proto_tree_add_ipv6_format	(*p_proto_tree_add_ipv6_format)
#define	proto_tree_add_ether		(*p_proto_tree_add_ether)
#define	proto_tree_add_ether_hidden	(*p_proto_tree_add_ether_hidden)
#define	proto_tree_add_ether_format	(*p_proto_tree_add_ether_format)
#define	proto_tree_add_string		(*p_proto_tree_add_string)
#define	proto_tree_add_string_hidden	(*p_proto_tree_add_string_hidden)
#define	proto_tree_add_string_format	(*p_proto_tree_add_string_format)
#define	proto_tree_add_boolean		(*p_proto_tree_add_boolean)
#define	proto_tree_add_boolean_hidden	(*p_proto_tree_add_boolean_hidden)
#define	proto_tree_add_boolean_format	(*p_proto_tree_add_boolean_format)
#define	proto_tree_add_double		(*p_proto_tree_add_double)
#define	proto_tree_add_double_hidden	(*p_proto_tree_add_double_hidden)
#define	proto_tree_add_double_format	(*p_proto_tree_add_double_format)
#define	proto_tree_add_uint		(*p_proto_tree_add_uint)
#define	proto_tree_add_uint_hidden	(*p_proto_tree_add_uint_hidden)
#define	proto_tree_add_uint_format	(*p_proto_tree_add_uint_format)
#define	proto_tree_add_int		(*p_proto_tree_add_int)
#define	proto_tree_add_int_hidden	(*p_proto_tree_add_int_hidden)
#define	proto_tree_add_int_format	(*p_proto_tree_add_int_format)
#define	proto_tree_add_text		(*p_proto_tree_add_text)

#define tvb_new_subset			(*p_tvb_new_subset)

#define tvb_set_free_cb			(*p_tvb_set_free_cb)
#define tvb_set_child_real_data_tvbuff	(*p_tvb_set_child_real_data_tvbuff)
#define tvb_new_real_data		(*p_tvb_new_real_data)

#define tvb_length			(*p_tvb_length)
#define tvb_length_remaining		(*p_tvb_length_remaining)
#define tvb_bytes_exist			(*p_tvb_bytes_exist)
#define tvb_offset_exists		(*p_tvb_offset_exists)
#define tvb_reported_length		(*p_tvb_reported_length)
#define tvb_reported_length_remaining	(*p_tvb_reported_length_remaining)

#define tvb_get_guint8			(*p_tvb_get_guint8)

#define tvb_get_ntohs			(*p_tvb_get_ntohs)
#define tvb_get_ntoh24			(*p_tvb_get_ntoh24)
#define tvb_get_ntohl			(*p_tvb_get_ntohl)

#define tvb_get_letohs			(*p_tvb_get_letohs)
#define tvb_get_letoh24			(*p_tvb_get_letoh24)
#define tvb_get_letohl			(*p_tvb_get_letohl)

#define tvb_memcpy			(*p_tvb_memcpy)
#define tvb_memdup			(*p_tvb_memdup)

#define tvb_get_ptr			(*p_tvb_get_ptr)

#define tvb_find_guint8			(*p_tvb_find_guint8)
#define tvb_pbrk_guint8			(*p_tvb_pbrk_guint8)

#define tvb_strnlen			(*p_tvb_strnlen)

#define tvb_format_text			(*p_tvb_format_text)

#define tvb_get_nstringz		(*p_tvb_get_nstringz)
#define tvb_get_nstringz0		(*p_tvb_get_nstringz0)

#define tvb_find_line_end		(*p_tvb_find_line_end)
#define tvb_find_line_end_unquoted	(*p_tvb_find_line_end_unquoted)

#define tvb_strneql			(*p_tvb_strneql)
#define tvb_strncaseeql			(*p_tvb_strncaseeql)

#define tvb_bytes_to_str		(*p_tvb_bytes_to_str)

#define prefs_register_protocol		(*p_prefs_register_protocol)
#define prefs_register_uint_preference	(*p_prefs_register_uint_preference)
#define prefs_register_bool_preference	(*p_prefs_register_bool_preference)
#define prefs_register_enum_preference	(*p_prefs_register_enum_preference)
#define prefs_register_string_preference (*p_prefs_register_string_preference)


/* GIOP entries Begin */

#define register_giop_user		(*p_register_giop_user)
#define is_big_endian			(*p_is_big_endian)
#define get_CDR_encap_info		(*p_get_CDR_encap_info)

#define get_CDR_any			(*p_get_CDR_any)
#define get_CDR_boolean			(*p_get_CDR_boolean)
#define get_CDR_char			(*p_get_CDR_char)
#define get_CDR_double			(*p_get_CDR_double)
#define get_CDR_enum			(*p_get_CDR_enum)
#define get_CDR_fixed			(*p_get_CDR_fixed)
#define get_CDR_float			(*p_get_CDR_float)
#define get_CDR_interface		(*p_get_CDR_interface)
#define get_CDR_long         	        (*p_get_CDR_long)
#define get_CDR_object			(*p_get_CDR_object)
#define get_CDR_octet         	        (*p_get_CDR_octet)
#define get_CDR_octet_seq     	        (*p_get_CDR_octet_seq)
#define get_CDR_short         	        (*p_get_CDR_short)
#define get_CDR_string			(*p_get_CDR_string)
#define get_CDR_typeCode		(*p_get_CDR_typeCode)
#define get_CDR_ulong			(*p_get_CDR_ulong)
#define get_CDR_ushort			(*p_get_CDR_ushort)
#define get_CDR_wchar			(*p_get_CDR_wchar)
#define get_CDR_wstring			(*p_get_CDR_wstring)

/* GIOP entries End */

#endif

#include <epan/packet.h>
#include <epan/conversation.h>
#include "prefs.h"
#include "packet-giop.h"

#include "plugin_table.h"

#ifdef PLUGINS_NEED_ADDRESS_TABLE
/* The parent executable will send us the pointer to a filled in
   plugin_address_table_t struct, and we copy the pointers from
   that table so that we can use functions from the parent executable. */
void plugin_address_table_init(plugin_address_table_t*);
#else
#define plugin_address_table_init(x)    ;
#endif

#endif /* PLUGIN_API_H */
