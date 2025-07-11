/* proto.c
 * Routines for protocol tree
 *
 * $Id: proto.c,v 1.51.2.5 2002/05/09 04:24:38 gram Exp $
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
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include "packet.h"
#include "strutil.h"
#include "resolv.h"
#include "plugins.h"
#include "ipv6-utils.h"
#include "proto.h"
#include "int-64bit.h"

#define cVALS(x) (const value_string*)(x)

static gboolean
proto_tree_free_node(GNode *node, gpointer data);

static void fill_label_boolean(field_info *fi, gchar *label_str);
static void fill_label_uint(field_info *fi, gchar *label_str);
static void fill_label_uint64(field_info *fi, gchar *label_str);
static void fill_label_int64(field_info *fi, gchar *label_str);
static void fill_label_enumerated_uint(field_info *fi, gchar *label_str);
static void fill_label_enumerated_bitfield(field_info *fi, gchar *label_str);
static void fill_label_numeric_bitfield(field_info *fi, gchar *label_str);
static void fill_label_int(field_info *fi, gchar *label_str);
static void fill_label_enumerated_int(field_info *fi, gchar *label_str);

int hfinfo_bitwidth(header_field_info *hfinfo);
static char* hfinfo_uint_vals_format(header_field_info *hfinfo);
static char* hfinfo_uint_format(header_field_info *hfinfo);
static char* hfinfo_int_vals_format(header_field_info *hfinfo);
static char* hfinfo_int_format(header_field_info *hfinfo);

static gboolean check_for_protocol_or_field_id(GNode *node, gpointer data);

static proto_item*
proto_tree_add_node(proto_tree *tree, field_info *fi);

static field_info *
alloc_field_info(proto_tree *tree, int hfindex, tvbuff_t *tvb,
        gint start, gint length);

static proto_item *
proto_tree_add_pi(proto_tree *tree, int hfindex, tvbuff_t *tvb,
        gint start, gint length, field_info **pfi);
static void
proto_tree_set_representation(proto_item *pi, const char *format, va_list ap);

static void
proto_tree_set_protocol_tvb(field_info *fi, tvbuff_t *tvb);
static void
proto_tree_set_uint64(field_info *fi, const guint8 *value_ptr, gboolean little_endian);
static void
proto_tree_set_uint64_tvb(field_info *fi, tvbuff_t *tvb, gint start, gboolean little_endian);
static void
proto_tree_set_bytes(field_info *fi, const guint8* start_ptr, gint length);
static void
proto_tree_set_bytes_tvb(field_info *fi, tvbuff_t *tvb, gint offset, gint length);
static void
proto_tree_set_time(field_info *fi, nstime_t *value_ptr);
static void
proto_tree_set_string(field_info *fi, const char* value, gboolean);
static void
proto_tree_set_string_tvb(field_info *fi, tvbuff_t *tvb, gint start, gint length);
static void
proto_tree_set_ether(field_info *fi, const guint8* value);
static void
proto_tree_set_ether_tvb(field_info *fi, tvbuff_t *tvb, gint start);
static void
proto_tree_set_ipxnet(field_info *fi, guint32 value);
static void
proto_tree_set_ipv4(field_info *fi, guint32 value);
static void
proto_tree_set_ipv6(field_info *fi, const guint8* value_ptr);
static void
proto_tree_set_ipv6_tvb(field_info *fi, tvbuff_t *tvb, gint start);
static void
proto_tree_set_boolean(field_info *fi, guint32 value);
static void
proto_tree_set_double(field_info *fi, double value);
static void
proto_tree_set_uint(field_info *fi, guint32 value);
static void
proto_tree_set_int(field_info *fi, gint32 value);

static int proto_register_field_init(header_field_info *hfinfo, int parent);

/* special-case header field used within proto.c */
int hf_text_only = 1;

/* Structure for information about a protocol */
typedef struct {
	char	*name;		/* long description */
	char	*short_name;	/* short description */
	char	*filter_name;	/* name of this protocol in filters */
	int	proto_id;	/* field ID for this protocol */
	GList	*fields;	/* fields for this protocol */
	GList	*last_field;	/* pointer to end of list of fields */
	gboolean is_enabled;	/* TRUE if protocol is enabled */
	gboolean can_disable;	/* TRUE if protocol can be disabled */
} protocol_t;

/* List of all protocols */
static GList *protocols;

#define INITIAL_NUM_PROTOCOL_HFINFO     200
#define INITIAL_NUM_FIELD_INFO          100
#define INITIAL_NUM_PROTO_NODE          100
#define INITIAL_NUM_ITEM_LABEL          100


/* Contains information about protocols and header fields. Used when
 * dissectors register their data */
static GMemChunk *gmc_hfinfo = NULL;

/* Contains information about a field when a dissector calls
 * proto_tree_add_item.  */
static GMemChunk *gmc_field_info = NULL;

/* Contains the space for proto_nodes. */
static GMemChunk *gmc_proto_node = NULL;

/* String space for protocol and field items for the GUI */
static GMemChunk *gmc_item_labels = NULL;

/* List which stores protocols and fields that have been registered */
static GPtrArray *gpa_hfinfo = NULL;

/* Points to the first element of an array of Booleans, indexed by
   a subtree item type; that array element is TRUE if subtrees of
   an item of that type are to be expanded. */
gboolean	*tree_is_expanded;

/* Number of elements in that array. */
int		num_tree_types;

/* initialize data structures and register protocols and fields */
void
proto_init(const char *plugin_dir,void (register_all_protocols)(void),
	   void (register_all_protocol_handoffs)(void))
{
	static hf_register_info hf[] = {
		{ &hf_text_only,
		{ "",	"", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	};

	if (gmc_hfinfo)
		g_mem_chunk_destroy(gmc_hfinfo);
	if (gmc_field_info)
		g_mem_chunk_destroy(gmc_field_info);
	if (gmc_proto_node)
		g_mem_chunk_destroy(gmc_proto_node);
	if (gmc_item_labels)
		g_mem_chunk_destroy(gmc_item_labels);
	if (gpa_hfinfo)
		g_ptr_array_free(gpa_hfinfo, TRUE);
	if (tree_is_expanded != NULL)
		g_free(tree_is_expanded);

	gmc_hfinfo = g_mem_chunk_new("gmc_hfinfo",
		sizeof(header_field_info),
        INITIAL_NUM_PROTOCOL_HFINFO * sizeof(header_field_info),
        G_ALLOC_ONLY);

	gmc_field_info = g_mem_chunk_new("gmc_field_info",
		sizeof(field_info),
        INITIAL_NUM_FIELD_INFO * sizeof(field_info),
		G_ALLOC_AND_FREE);

	gmc_proto_node = g_mem_chunk_new("gmc_proto_node",
		sizeof(proto_node),
        INITIAL_NUM_PROTO_NODE * sizeof(proto_node),
		G_ALLOC_AND_FREE);

	gmc_item_labels = g_mem_chunk_new("gmc_item_labels",
		ITEM_LABEL_LENGTH,
        INITIAL_NUM_ITEM_LABEL* ITEM_LABEL_LENGTH,
		G_ALLOC_AND_FREE);

	gpa_hfinfo = g_ptr_array_new();

	/* Allocate "tree_is_expanded", with one element for ETT_NONE,
	   and initialize that element to FALSE. */
	tree_is_expanded = g_malloc(sizeof (gint));
	tree_is_expanded[0] = FALSE;
	num_tree_types = 1;

	/* Initialize the ftype subsystem */
	ftypes_initialize();

	/* Have each built-in dissector register its protocols, fields,
	   dissector tables, and dissectors to be called through a
	   handle, and do whatever one-time initialization it needs to
	   do. */
	register_all_protocols();

#ifdef HAVE_PLUGINS
	/* Now scan for plugins and load all the ones we find, calling
	   their register routines to do the stuff described above. */
	init_plugins(plugin_dir);
#endif

	/* Now call the "handoff registration" routines of all built-in
	   dissectors; those routines register the dissector in other
	   dissectors' handoff tables, and fetch any dissector handles
	   they need. */
	register_all_protocol_handoffs();

#ifdef HAVE_PLUGINS
	/* Now do the same with plugins. */
	register_all_plugin_handoffs();
#endif

	/* Register one special-case FT_TEXT_ONLY field for use when
	   converting ethereal to new-style proto_tree. These fields
	   are merely strings on the GUI tree; they are not filterable */
	proto_register_field_array(-1, hf, array_length(hf));

	/* We've assigned all the subtree type values; allocate the array
	   for them, and zero it out. */
	tree_is_expanded = g_malloc(num_tree_types*sizeof (gint *));
	memset(tree_is_expanded, '\0', num_tree_types*sizeof (gint *));
}

void
proto_cleanup(void)
{
	if (gmc_hfinfo)
		g_mem_chunk_destroy(gmc_hfinfo);
	if (gmc_field_info)
		g_mem_chunk_destroy(gmc_field_info);
	if (gmc_proto_node)
		g_mem_chunk_destroy(gmc_proto_node);
	if (gmc_item_labels)
		g_mem_chunk_destroy(gmc_item_labels);
	if (gpa_hfinfo)
		g_ptr_array_free(gpa_hfinfo, TRUE);
	if (tree_is_expanded != NULL)
		g_free(tree_is_expanded);

	/* Cleanup the ftype subsystem */
	ftypes_cleanup();
}

/* frees the resources that the dissection a proto_tree uses */
void
proto_tree_free(proto_tree *tree)
{
    /* Free all the data pointed to by the tree. */
	g_node_traverse((GNode*)tree, G_IN_ORDER, G_TRAVERSE_ALL, -1,
		proto_tree_free_node, NULL);

    /* Then free the tree. */
	g_node_destroy((GNode*)tree);
}

/* We accept a void* instead of a field_info* to satisfy CLEANUP_POP */
static void
free_field_info(void *fi)
{
	g_mem_chunk_free(gmc_field_info, (field_info*)fi);
}

static void
free_GPtrArray_value(gpointer key, gpointer value, gpointer user_data)
{
    GPtrArray   *ptrs = value;

    g_ptr_array_free(ptrs, TRUE);
}

static void
free_node_tree_data(tree_data_t *tree_data)
{
        /* Free all the GPtrArray's in the interesting_hfids hash. */
        g_hash_table_foreach(tree_data->interesting_hfids,
            free_GPtrArray_value, NULL);

        /* And then destroy the hash. */
        g_hash_table_destroy(tree_data->interesting_hfids);

        /* And finally the tree_data_t itself. */
        g_free(tree_data);
}

static void
free_node_field_info(field_info* finfo)
{
		if (finfo->representation) {
			g_mem_chunk_free(gmc_item_labels, finfo->representation);
		}
		fvalue_free(finfo->value);
		free_field_info(finfo);
}

static gboolean
proto_tree_free_node(GNode *node, gpointer data)
{
	field_info *finfo = PITEM_FINFO(node);

    if (finfo == NULL) {
        /* This is the root GNode. Destroy the per-tree data.
         * There is no field_info to destroy. */
        free_node_tree_data(PTREE_DATA(node));
    }
    else {
        /* This is a child GNode. Don't free the per-tree data, but
         * do free the field_info data. */
        free_node_field_info(finfo);
	}

    /* Free the proto_node. */
	g_mem_chunk_free(gmc_proto_node, GNODE_PNODE(node));

	return FALSE; /* FALSE = do not end traversal of GNode tree */
}

/* Is the parsing being done for a visible proto_tree or an invisible one?
 * By setting this correctly, the proto_tree creation is sped up by not
 * having to call vsnprintf and copy strings around.
 */
void
proto_tree_set_visible(proto_tree *tree, gboolean visible)
{
    PTREE_DATA(tree)->visible = visible;
}

/* Finds a record in the hf_info_records array by id. */
header_field_info*
proto_registrar_get_nth(int hfindex)
{
	g_assert(hfindex >= 0 && (guint) hfindex < gpa_hfinfo->len);
	return g_ptr_array_index(gpa_hfinfo, hfindex);
}


/* Add a text-only node, leaving it to our caller to fill the text in */
static proto_item *
proto_tree_add_text_node(proto_tree *tree, tvbuff_t *tvb, gint start, gint length)
{
	proto_item	*pi;

	pi = proto_tree_add_pi(tree, hf_text_only, tvb, start, length, NULL);
	if (pi == NULL)
		return(NULL);

	return pi;
}

/* Add a text-only node to the proto_tree */
proto_item *
proto_tree_add_text(proto_tree *tree, tvbuff_t *tvb, gint start, gint length,
	const char *format, ...)
{
	proto_item	*pi;
	va_list		ap;

	pi = proto_tree_add_text_node(tree, tvb, start, length);
	if (pi == NULL)
		return(NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Add a text-only node to the proto_tree (va_list version) */
proto_item *
proto_tree_add_text_valist(proto_tree *tree, tvbuff_t *tvb, gint start, 
	gint length, const char *format, va_list ap)
{
	proto_item	*pi;

	pi = proto_tree_add_text_node(tree, tvb, start, length);
	if (pi == NULL)
		return(NULL);

	proto_tree_set_representation(pi, format, ap);

	return pi;
}

/* Add a text-only node for debugging purposes. The caller doesn't need
 * to worry about tvbuff, start, or length. Debug message gets sent to
 * STDOUT, too */
proto_item *
proto_tree_add_debug_text(proto_tree *tree, const char *format, ...)
{
	proto_item	*pi;
	va_list		ap;

	pi = proto_tree_add_text_node(tree, NULL, 0, 0);
	if (pi == NULL)
		return(NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	vprintf(format, ap);
	va_end(ap);
	printf("\n");

	return pi;
}


static guint32
get_uint_value(tvbuff_t *tvb, gint offset, gint length, gboolean little_endian)
{
	guint32 value;

	switch (length) {

	case 1:
		value = tvb_get_guint8(tvb, offset);
		break;

	case 2:
		value = little_endian ? tvb_get_letohs(tvb, offset)
				      : tvb_get_ntohs(tvb, offset);
		break;

	case 3:
		value = little_endian ? tvb_get_letoh24(tvb, offset)
				      : tvb_get_ntoh24(tvb, offset);
		break;

	case 4:
		value = little_endian ? tvb_get_letohl(tvb, offset)
				      : tvb_get_ntohl(tvb, offset);
		break;

	default:
		g_assert_not_reached();
		value = 0;
		break;
	}
	return value;
}

static gint32
get_int_value(tvbuff_t *tvb, gint offset, gint length, gboolean little_endian)
{
	gint32 value;

	switch (length) {

	case 1:
		value = (gint8)tvb_get_guint8(tvb, offset);
		break;

	case 2:
		value = (gint16) (little_endian ? tvb_get_letohs(tvb, offset)
						: tvb_get_ntohs(tvb, offset));
		break;

	case 3:
		value = little_endian ? tvb_get_letoh24(tvb, offset)
				      : tvb_get_ntoh24(tvb, offset);
		if (value & 0x00800000) {
			/* Sign bit is set; sign-extend it. */
			value |= 0xFF000000;
		}
		break;

	case 4:
		value = little_endian ? tvb_get_letohl(tvb, offset)
				      : tvb_get_ntohl(tvb, offset);
		break;

	default:
		g_assert_not_reached();
		value = 0;
		break;
	}
	return value;
}

/* Add an item to a proto_tree, using the text label registered to that item;
   the item is extracted from the tvbuff handed to it. */
proto_item *
proto_tree_add_item(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, gboolean little_endian)
{
	field_info	*new_fi;
	proto_item	*pi;
	guint32		value, n;
	char		*string;
	int		found_length;
    GHashTable  *hash;
    GPtrArray   *ptrs;

	if (!tree)
		return(NULL);

	new_fi = alloc_field_info(tree, hfindex, tvb, start, length);

	if (new_fi == NULL)
		return(NULL);

	/* Register a cleanup function in case on of our tvbuff accesses
	 * throws an exception. We need to clean up new_fi. */
	CLEANUP_PUSH(free_field_info, new_fi);

	switch(new_fi->hfinfo->type) {
		case FT_NONE:
			/* no value to set for FT_NONE */
			break;

		case FT_PROTOCOL:
			proto_tree_set_protocol_tvb(new_fi, tvb);
			break;

		case FT_BYTES:
			proto_tree_set_bytes_tvb(new_fi, tvb, start, length);
			break;

		case FT_UINT_BYTES:
			n = get_uint_value(tvb, start, length, little_endian);
			proto_tree_set_bytes_tvb(new_fi, tvb, start + length, n);

			/* Instead of calling proto_item_set_len(), since we don't yet
			 * have a proto_item, we set the field_info's length ourselves. */
			new_fi->length = n + length;
			break;

		case FT_BOOLEAN:
			proto_tree_set_boolean(new_fi,
			    get_uint_value(tvb, start, length, little_endian));
			break;

		/* XXX - make these just FT_UINT? */
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
			proto_tree_set_uint(new_fi,
			    get_uint_value(tvb, start, length, little_endian));
			break;

		case FT_INT64:
		case FT_UINT64:
			g_assert(length == 8);
			proto_tree_set_uint64_tvb(new_fi, tvb, start, little_endian);
			break;

		/* XXX - make these just FT_INT? */
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			proto_tree_set_int(new_fi,
			    get_int_value(tvb, start, length, little_endian));
			break;

		case FT_IPv4:
			g_assert(length == 4);
			tvb_memcpy(tvb, (guint8 *)&value, start, 4);
			proto_tree_set_ipv4(new_fi, value);
			break;

		case FT_IPXNET:
			g_assert(length == 4);
			proto_tree_set_ipxnet(new_fi,
			    get_uint_value(tvb, start, 4, FALSE));
			break;

		case FT_IPv6:
			g_assert(length == 16);
			proto_tree_set_ipv6_tvb(new_fi, tvb, start);
			break;

		case FT_ETHER:
			g_assert(length == 6);
			proto_tree_set_ether_tvb(new_fi, tvb, start);
			break;

		case FT_STRING:
			/* This g_strdup'ed memory is freed in proto_tree_free_node() */
			proto_tree_set_string_tvb(new_fi, tvb, start, length);
			break;

		case FT_STRINGZ:
			if (length == PROTO_LENGTH_UNTIL_END) {
				/* This can throw an exception */
				length = tvb_strsize(tvb, start);

				/* This g_strdup'ed memory is freed in proto_tree_free_node() */
				string = g_malloc(length);

				tvb_memcpy(tvb, string, start, length);
				new_fi->length = length;
			}
			else {
				/* In this case, length signifies maximum length. */

				/* This g_strdup'ed memory is freed in proto_tree_free_node() */
				string = g_malloc(length);

				CLEANUP_PUSH(g_free, string);

				found_length = tvb_get_nstringz0(tvb, start, length, string);

				CLEANUP_POP;
				new_fi->length = found_length + 1;
			}
			proto_tree_set_string(new_fi, string, TRUE);

			break;

		case FT_UINT_STRING:
			/* This g_strdup'ed memory is freed in proto_tree_free_node() */
			n = get_uint_value(tvb, start, length, little_endian);
			proto_tree_set_string_tvb(new_fi, tvb, start + length, n);

			/* Instead of calling proto_item_set_len(), since we don't yet
			 * have a proto_item, we set the field_info's length ourselves. */
			new_fi->length = n + length;
			break;
		default:
			g_error("new_fi->hfinfo->type %d (%s) not handled\n",
					new_fi->hfinfo->type,
					ftype_name(new_fi->hfinfo->type));
			g_assert_not_reached();
			break;

	}
	CLEANUP_POP;

	/* Don't add new node to proto_tree until now so that any exceptions
	 * raised by a tvbuff access method doesn't leave junk in the proto_tree. */
	pi = proto_tree_add_node(tree, new_fi);

    /* If the proto_tree wants to keep a record of this finfo
     * for quick lookup, then record it. */
    hash = PTREE_DATA(tree)->interesting_hfids;
    ptrs = g_hash_table_lookup(hash, GINT_TO_POINTER(hfindex));
    if (ptrs) {
        g_ptr_array_add(ptrs, new_fi);
    }

	return pi;
}

proto_item *
proto_tree_add_item_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb,
    gint start, gint length, gboolean little_endian)
{
	proto_item	*pi;
	field_info	*fi;

	pi = proto_tree_add_item(tree, hfindex, tvb, start, length, little_endian);
	if (pi == NULL)
		return(NULL);

	fi = PITEM_FINFO(pi);
	fi->visible = FALSE;

	return pi;
}


/* Add a FT_NONE to a proto_tree */
proto_item *
proto_tree_add_none_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		gint length, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	hfinfo = proto_registrar_get_nth(hfindex);
	g_assert(hfinfo->type == FT_NONE);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, length, NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	/* no value to set for FT_NONE */
	return pi;
}

	
static void
proto_tree_set_protocol_tvb(field_info *fi, tvbuff_t *tvb)
{
	fvalue_set(fi->value, tvb, TRUE);
}

/* Add a FT_PROTOCOL to a proto_tree */
proto_item *
proto_tree_add_protocol_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		gint length, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;
	header_field_info	*hfinfo;
	field_info		*new_fi;

	if (!tree)
		return (NULL);

	hfinfo = proto_registrar_get_nth(hfindex);
	g_assert(hfinfo->type == FT_PROTOCOL);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, length, &new_fi);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	if (start == 0) {
		proto_tree_set_protocol_tvb(new_fi, tvb);
	}
	else {
		proto_tree_set_protocol_tvb(new_fi, NULL);
	}
	return pi;
}


/* Add a FT_BYTES to a proto_tree */
proto_item *
proto_tree_add_bytes(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		gint length, const guint8 *start_ptr)
{
	proto_item		*pi;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	hfinfo = proto_registrar_get_nth(hfindex);
	g_assert(hfinfo->type == FT_BYTES);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, length, &new_fi);
	proto_tree_set_bytes(new_fi, start_ptr, length);

	return pi;
}

proto_item *
proto_tree_add_bytes_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		gint length, const guint8 *start_ptr)
{
	proto_item		*pi;
	field_info 		*fi;

	pi = proto_tree_add_bytes(tree, hfindex, tvb, start, length, start_ptr);
	if (pi == NULL)
		return (NULL);

	fi = PITEM_FINFO(pi);
	fi->visible = FALSE;

	return pi;
}

proto_item *
proto_tree_add_bytes_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		gint length, const guint8 *start_ptr, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_bytes(tree, hfindex, tvb, start, length, start_ptr);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

static void
proto_tree_set_bytes(field_info *fi, const guint8* start_ptr, gint length)
{
	GByteArray		*bytes;

	bytes = g_byte_array_new();
	if (length > 0) {
		g_byte_array_append(bytes, start_ptr, length);
	}
	fvalue_set(fi->value, bytes, TRUE);
}


static void
proto_tree_set_bytes_tvb(field_info *fi, tvbuff_t *tvb, gint offset, gint length)
{
	proto_tree_set_bytes(fi, tvb_get_ptr(tvb, offset, length), length);
}

/* Add a FT_*TIME to a proto_tree */
proto_item *
proto_tree_add_time(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		nstime_t *value_ptr)
{
	proto_item		*pi;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	hfinfo = proto_registrar_get_nth(hfindex);
	g_assert(hfinfo->type == FT_ABSOLUTE_TIME ||
				hfinfo->type == FT_RELATIVE_TIME);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, length, &new_fi);
	proto_tree_set_time(new_fi, value_ptr);

	return pi;
}

proto_item *
proto_tree_add_time_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		nstime_t *value_ptr)
{
	proto_item		*pi;
	field_info 		*fi;

	pi = proto_tree_add_time(tree, hfindex, tvb, start, length, value_ptr);
	if (pi == NULL)
		return (NULL);

	fi = PITEM_FINFO(pi);
	fi->visible = FALSE;

	return pi;
}

proto_item *
proto_tree_add_time_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		nstime_t *value_ptr, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_time(tree, hfindex, tvb, start, length, value_ptr);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_*TIME value */
static void
proto_tree_set_time(field_info *fi, nstime_t *value_ptr)
{
	fvalue_set(fi->value, value_ptr, FALSE);
}

/* Add a FT_IPXNET to a proto_tree */
proto_item *
proto_tree_add_ipxnet(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint32 value)
{
	proto_item		*pi;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	hfinfo = proto_registrar_get_nth(hfindex);
	g_assert(hfinfo->type == FT_IPXNET);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, length, &new_fi);
	proto_tree_set_ipxnet(new_fi, value);

	return pi;
}

proto_item *
proto_tree_add_ipxnet_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint32 value)
{
	proto_item		*pi;
	field_info 		*fi;

	pi = proto_tree_add_ipxnet(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	fi = PITEM_FINFO(pi);
	fi->visible = FALSE;

	return pi;
}

proto_item *
proto_tree_add_ipxnet_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint32 value, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_ipxnet(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_IPXNET value */
static void
proto_tree_set_ipxnet(field_info *fi, guint32 value)
{
	fvalue_set_integer(fi->value, value);
}

/* Add a FT_IPv4 to a proto_tree */
proto_item *
proto_tree_add_ipv4(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint32 value)
{
	proto_item		*pi;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	hfinfo = proto_registrar_get_nth(hfindex);
	g_assert(hfinfo->type == FT_IPv4);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, length, &new_fi);
	proto_tree_set_ipv4(new_fi, value);

	return pi;
}

proto_item *
proto_tree_add_ipv4_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint32 value)
{
	proto_item		*pi;
	field_info 		*fi;

	pi = proto_tree_add_ipv4(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	fi = PITEM_FINFO(pi);
	fi->visible = FALSE;

	return pi;
}

proto_item *
proto_tree_add_ipv4_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint32 value, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_ipv4(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_IPv4 value */
static void
proto_tree_set_ipv4(field_info *fi, guint32 value)
{
	fvalue_set_integer(fi->value, value);
}

/* Add a FT_IPv6 to a proto_tree */
proto_item *
proto_tree_add_ipv6(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		const guint8* value_ptr)
{
	proto_item		*pi;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	hfinfo = proto_registrar_get_nth(hfindex);
	g_assert(hfinfo->type == FT_IPv6);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, length, &new_fi);
	proto_tree_set_ipv6(new_fi, value_ptr);

	return pi;
}

proto_item *
proto_tree_add_ipv6_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		const guint8* value_ptr)
{
	proto_item		*pi;
	field_info 		*fi;

	pi = proto_tree_add_ipv6(tree, hfindex, tvb, start, length, value_ptr);
	if (pi == NULL)
		return (NULL);

	fi = PITEM_FINFO(pi);
	fi->visible = FALSE;

	return pi;
}

proto_item *
proto_tree_add_ipv6_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		const guint8* value_ptr, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_ipv6(tree, hfindex, tvb, start, length, value_ptr);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_IPv6 value */
static void
proto_tree_set_ipv6(field_info *fi, const guint8* value_ptr)
{
	fvalue_set(fi->value, (gpointer) value_ptr, FALSE);
}

static void
proto_tree_set_ipv6_tvb(field_info *fi, tvbuff_t *tvb, gint start)
{
	proto_tree_set_ipv6(fi, tvb_get_ptr(tvb, start, 16));
}

static void
proto_tree_set_uint64(field_info *fi, const guint8 *value_ptr, gboolean little_endian)
{
	if(little_endian){
		unsigned char buffer[8];
		int i;

		for(i=0;i<8;i++){
			buffer[i]=value_ptr[7-i];
		}
		fvalue_set(fi->value, (gpointer)buffer, FALSE);
	} else {
		fvalue_set(fi->value, (gpointer)value_ptr, FALSE);
	}
}

static void
proto_tree_set_uint64_tvb(field_info *fi, tvbuff_t *tvb, gint start, gboolean little_endian)
{
	proto_tree_set_uint64(fi, tvb_get_ptr(tvb, start, 8), little_endian);
}

/* Add a FT_STRING to a proto_tree */
proto_item *
proto_tree_add_string(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		gint length, const char* value)
{
	proto_item		*pi;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	hfinfo = proto_registrar_get_nth(hfindex);
	g_assert(hfinfo->type == FT_STRING);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, length, &new_fi);
	proto_tree_set_string(new_fi, value, FALSE);

	return pi;
}

proto_item *
proto_tree_add_string_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		gint length, const char* value)
{
	proto_item		*pi;
	field_info 		*fi;

	pi = proto_tree_add_string(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	fi = PITEM_FINFO(pi);
	fi->visible = FALSE;

	return pi;
}

proto_item *
proto_tree_add_string_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
		gint length, const char* value, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_string(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_STRING value */
static void
proto_tree_set_string(field_info *fi, const char* value,
		gboolean already_allocated)
{
	fvalue_set(fi->value, (gpointer) value, already_allocated);
}

static void
proto_tree_set_string_tvb(field_info *fi, tvbuff_t *tvb, gint start, gint length)
{
	gchar	*string;

	if (length == PROTO_LENGTH_UNTIL_END) {
		length = tvb_ensure_length_remaining(tvb, start);
	}

	/* This memory is freed in proto_tree_free_node() */
	string = g_malloc(length + 1);
	tvb_memcpy(tvb, string, start, length);
	string[length] = '\0';
	proto_tree_set_string(fi, string, TRUE);
}

/* Add a FT_ETHER to a proto_tree */
proto_item *
proto_tree_add_ether(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		const guint8* value)
{
	proto_item		*pi;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	hfinfo = proto_registrar_get_nth(hfindex);
	g_assert(hfinfo->type == FT_ETHER);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, length, &new_fi);
	proto_tree_set_ether(new_fi, value);

	return pi;
}

proto_item *
proto_tree_add_ether_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		const guint8* value)
{
	proto_item		*pi;
	field_info 		*fi;

	pi = proto_tree_add_ether(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	fi = PITEM_FINFO(pi);
	fi->visible = FALSE;

	return pi;
}

proto_item *
proto_tree_add_ether_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		const guint8* value, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_ether(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_ETHER value */
static void
proto_tree_set_ether(field_info *fi, const guint8* value)
{
	fvalue_set(fi->value, (gpointer) value, FALSE);
}

static void
proto_tree_set_ether_tvb(field_info *fi, tvbuff_t *tvb, gint start)
{
	proto_tree_set_ether(fi, tvb_get_ptr(tvb, start, 6));
}

/* Add a FT_BOOLEAN to a proto_tree */
proto_item *
proto_tree_add_boolean(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint32 value)
{
	proto_item		*pi;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	hfinfo = proto_registrar_get_nth(hfindex);
	g_assert(hfinfo->type == FT_BOOLEAN);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, length, &new_fi);
	proto_tree_set_boolean(new_fi, value);

	return pi;
}

proto_item *
proto_tree_add_boolean_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint32 value)
{
	proto_item		*pi;
	field_info 		*fi;

	pi = proto_tree_add_boolean(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	fi = PITEM_FINFO(pi);
	fi->visible = FALSE;

	return pi;
}

proto_item *
proto_tree_add_boolean_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint32 value, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_boolean(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_BOOLEAN value */
static void
proto_tree_set_boolean(field_info *fi, guint32 value)
{
	proto_tree_set_uint(fi, value);
}

/* Add a FT_DOUBLE to a proto_tree */
proto_item *
proto_tree_add_double(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		double value)
{
	proto_item		*pi;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	hfinfo = proto_registrar_get_nth(hfindex);
	g_assert(hfinfo->type == FT_DOUBLE);

	pi = proto_tree_add_pi(tree, hfindex, tvb, start, length, &new_fi);
	proto_tree_set_double(new_fi, value);

	return pi;
}

proto_item *
proto_tree_add_double_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		double value)
{
	proto_item		*pi;
	field_info 		*fi;

	pi = proto_tree_add_double(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	fi = PITEM_FINFO(pi);
	fi->visible = FALSE;

	return pi;
}

proto_item *
proto_tree_add_double_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		double value, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_double(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_DOUBLE value */
static void
proto_tree_set_double(field_info *fi, double value)
{
	fvalue_set_floating(fi->value, value);
}

/* Add any FT_UINT* to a proto_tree */
proto_item *
proto_tree_add_uint(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint32 value)
{
	proto_item		*pi = NULL;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	hfinfo = proto_registrar_get_nth(hfindex);
	switch(hfinfo->type) {
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
			pi = proto_tree_add_pi(tree, hfindex, tvb, start, length,
					&new_fi);
			proto_tree_set_uint(new_fi, value);
			break;

		default:
			g_assert_not_reached();
	}

	return pi;
}

proto_item *
proto_tree_add_uint_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint32 value)
{
	proto_item		*pi;
	field_info 		*fi;

	pi = proto_tree_add_uint(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	fi = PITEM_FINFO(pi);
	fi->visible = FALSE;

	return pi;
}

proto_item *
proto_tree_add_uint_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		guint32 value, const char *format, ...)
{
	proto_item		*pi;
	va_list			ap;

	pi = proto_tree_add_uint(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_UINT* value */
static void
proto_tree_set_uint(field_info *fi, guint32 value)
{
	header_field_info	*hfinfo;
	guint32			integer;

	hfinfo = fi->hfinfo;
	integer = value;

	if (hfinfo->bitmask) {
		/* Mask out irrelevant portions */
		integer &= hfinfo->bitmask;

		/* Shift bits */
		if (hfinfo->bitshift > 0) {
			integer >>= hfinfo->bitshift;
		}
	}
	fvalue_set_integer(fi->value, integer);
}

/* Add any FT_INT* to a proto_tree */
proto_item *
proto_tree_add_int(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		gint32 value)
{
	proto_item		*pi = NULL;
	field_info		*new_fi;
	header_field_info	*hfinfo;

	if (!tree)
		return (NULL);

	hfinfo = proto_registrar_get_nth(hfindex);
	switch(hfinfo->type) {
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			pi = proto_tree_add_pi(tree, hfindex, tvb, start, length,
					&new_fi);
			proto_tree_set_int(new_fi, value);
			break;

		default:
			g_assert_not_reached();
	}

	return pi;
}

proto_item *
proto_tree_add_int_hidden(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		gint32 value)
{
	proto_item		*pi;
	field_info 		*fi;

	pi = proto_tree_add_int(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	fi = PITEM_FINFO(pi);
	fi->visible = FALSE;

	return pi;
}

proto_item *
proto_tree_add_int_format(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		gint32 value, const char *format, ...)
{
	proto_item		*pi = NULL;
	va_list			ap;

	pi = proto_tree_add_int(tree, hfindex, tvb, start, length, value);
	if (pi == NULL)
		return (NULL);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);

	return pi;
}

/* Set the FT_INT* value */
static void
proto_tree_set_int(field_info *fi, gint32 value)
{
	header_field_info	*hfinfo;
	guint32			integer;

	hfinfo = fi->hfinfo;
	integer = (guint32) value;

	if (hfinfo->bitmask) {
		/* Mask out irrelevant portions */
		integer &= hfinfo->bitmask;

		/* Shift bits */
		if (hfinfo->bitshift > 0) {
			integer >>= hfinfo->bitshift;
		}
	}
	fvalue_set_integer(fi->value, integer);
}


/* Add a field_info struct to the proto_tree, encapsulating it in a GNode (proto_item) */
static proto_item *
proto_tree_add_node(proto_tree *tree, field_info *fi)
{
	GNode *new_gnode;
	proto_node *pnode;

	pnode = g_mem_chunk_alloc(gmc_proto_node);
	pnode->finfo = fi;
	pnode->tree_data = PTREE_DATA(tree);

	new_gnode = g_node_new(pnode);
	g_node_append((GNode*)tree, new_gnode);

	return (proto_item*) new_gnode;
}


/* Generic way to allocate field_info and add to proto_tree.
 * Sets *pfi to address of newly-allocated field_info struct, if pfi is
 * non-NULL. */
static proto_item *
proto_tree_add_pi(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length,
		field_info **pfi)
{
	proto_item	*pi;
	field_info	*fi;
	GHashTable	*hash;
	GPtrArray	*ptrs;

	if (!tree)
		return(NULL);

	fi = alloc_field_info(tree, hfindex, tvb, start, length);
	pi = proto_tree_add_node(tree, fi);

	/* If the proto_tree wants to keep a record of this finfo
	 * for quick lookup, then record it. */
	hash = PTREE_DATA(tree)->interesting_hfids;
	ptrs = g_hash_table_lookup(hash, GINT_TO_POINTER(hfindex));
	if (ptrs) {
		g_ptr_array_add(ptrs, fi);
	}

	/* Does the caller want to know the fi pointer? */
	if (pfi) {
		*pfi = fi;
	}

	return pi;
}

static field_info *
alloc_field_info(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length)
{
	header_field_info	*hfinfo;
	field_info		*fi;

	/*
	 * We only allow a null tvbuff if the item has a zero length,
	 * i.e. if there's no data backing it.
	 */
	g_assert(tvb != NULL || length == 0);

	g_assert(hfindex >= 0 && (guint) hfindex < gpa_hfinfo->len);
	hfinfo = proto_registrar_get_nth(hfindex);
	g_assert(hfinfo != NULL);

	if (length == PROTO_LENGTH_UNTIL_END) {
		/*
		 * For FT_NONE or FT_PROTOCOL fields, this means "set the
		 * length to what remains in the tvbuff"; the assumption
		 * is that the length can only be determined by dissection,
		 * so we set it to that value so that, if we throw an
		 * exception while dissecting, it has what is probably the
		 * right value.
		 *
		 * It's not valid for any other type of field.
		 */
		g_assert(hfinfo->type == FT_PROTOCOL ||
			 hfinfo->type == FT_NONE ||
			 hfinfo->type == FT_BYTES ||
			 hfinfo->type == FT_STRING ||
			 hfinfo->type == FT_STRINGZ);
		length = tvb_ensure_length_remaining(tvb, start);
	}

	fi = g_mem_chunk_alloc(gmc_field_info);
	fi->hfinfo = hfinfo;
	fi->start = start;
	if (tvb) {
		fi->start += tvb_raw_offset(tvb);
	}
	fi->length = length;
	fi->tree_type = ETT_NONE;
	fi->visible = PTREE_DATA(tree)->visible;
	fi->representation = NULL;

	fi->value = fvalue_new(fi->hfinfo->type);

	/* add the data source name */
	if (tvb) {
		fi->ds_name = tvb_get_name(tvb);
	} else {
		fi->ds_name = NULL;
	}

	return fi;
}

/* Set representation of a proto_tree entry, if the protocol tree is to
   be visible. */
static void
proto_tree_set_representation(proto_item *pi, const char *format, va_list ap)
{
	field_info *fi = PITEM_FINFO(pi);

	if (fi->visible) {
		fi->representation = g_mem_chunk_alloc(gmc_item_labels);
		vsnprintf(fi->representation, ITEM_LABEL_LENGTH, format, ap);
	}
}

/* Set text of proto_item after having already been created. */
void
proto_item_set_text(proto_item *pi, const char *format, ...)
{
	field_info *fi = NULL;
	va_list	ap;

	if (pi==NULL) {
		return;
	}

	fi = PITEM_FINFO(pi);

	if (fi->representation)
		g_mem_chunk_free(gmc_item_labels, fi->representation);

	va_start(ap, format);
	proto_tree_set_representation(pi, format, ap);
	va_end(ap);
}

/* Append to text of proto_item after having already been created. */
void
proto_item_append_text(proto_item *pi, const char *format, ...)
{
	field_info *fi = NULL;
	size_t curlen;
	va_list	ap;

	if (pi==NULL) {
		return;
	}

	fi = PITEM_FINFO(pi);

	if (fi->visible) {
		va_start(ap, format);
		/*
		 * XXX - this will blow up if we haven't already set
		 * "fi->representation"; that seems OK to me - you
		 * can't append to something that doesn't exist - but
		 * there might be cases where that's not convenient.
		 */
		curlen = strlen(fi->representation);
		if (ITEM_LABEL_LENGTH > curlen)
			vsnprintf(fi->representation + curlen,
			    ITEM_LABEL_LENGTH - curlen, format, ap);
		va_end(ap);
	}
}

void
proto_item_set_len(proto_item *pi, gint length)
{
	field_info *fi;
	
	if (pi == NULL)
		return;
	fi = PITEM_FINFO(pi);
	fi->length = length;
}

int
proto_item_get_len(proto_item *pi)
{
	field_info *fi = PITEM_FINFO(pi);
	return fi->length;
}

proto_tree*
proto_tree_create_root(void)
{
    proto_node  *pnode;

    /* Initialize the proto_node */
    pnode = g_mem_chunk_alloc(gmc_proto_node);
    pnode->finfo = NULL;
    pnode->tree_data = g_new(tree_data_t, 1);

    /* Initialize the tree_data_t */
    pnode->tree_data->interesting_hfids =
        g_hash_table_new(g_direct_hash, g_direct_equal);

    /* Set the default to FALSE so it's easier to
     * find errors; if we expect to see the protocol tree
     * but for some reason the default 'visible' is not
     * changed, then we'll find out very quickly. */
    pnode->tree_data->visible = FALSE;

	return (proto_tree*) g_node_new(pnode);
}

	
/* "prime" a proto_tree with a single hfid that a dfilter
 * is interested in. */
void
proto_tree_prime_hfid(proto_tree *tree, gint hfid)
{
	g_hash_table_insert(PTREE_DATA(tree)->interesting_hfids,
		GINT_TO_POINTER(hfid), g_ptr_array_new());
}


proto_tree*
proto_item_add_subtree(proto_item *pi,  gint idx) {
	field_info *fi;

	if (!pi)
		return(NULL);

	fi = PITEM_FINFO(pi);
	g_assert(idx >= 0 && idx < num_tree_types);
	fi->tree_type = idx;
	return (proto_tree*) pi;
}

static gint
proto_compare_name(gconstpointer p1_arg, gconstpointer p2_arg)
{
	const protocol_t *p1 = p1_arg;
	const protocol_t *p2 = p2_arg;

	return g_strcasecmp(p1->short_name, p2->short_name);
}

int
proto_register_protocol(char *name, char *short_name, char *filter_name)
{
	protocol_t *protocol;
	header_field_info *hfinfo;
	int proto_id;

	/* Add this protocol to the list of known protocols; the list
	   is sorted by protocol short name. */
	protocol = g_malloc(sizeof (protocol_t));
	protocol->name = name;
	protocol->short_name = short_name;
	protocol->filter_name = filter_name;
	protocol->fields = NULL;
	protocol->is_enabled = TRUE; /* protocol is enabled by default */
	protocol->can_disable = TRUE;
	protocols = g_list_insert_sorted(protocols, protocol,
	    proto_compare_name);

	/* Here we do allocate a new header_field_info struct */
	hfinfo = g_mem_chunk_alloc(gmc_hfinfo);
	hfinfo->name = name;
	hfinfo->abbrev = filter_name;
	hfinfo->type = FT_PROTOCOL;
	hfinfo->strings = NULL;
	hfinfo->bitmask = 0;
	hfinfo->bitshift = 0;
	hfinfo->blurb = "";
	hfinfo->parent = -1; /* this field differentiates protos and fields */

	proto_id = proto_register_field_init(hfinfo, hfinfo->parent);
	protocol->proto_id = proto_id;
	return proto_id;
}

/*
 * Routines to use to iterate over the protocols.
 * The argument passed to the iterator routines is an opaque cookie to
 * their callers; it's the GList pointer for the current element in
 * the list.
 * The ID of the protocol is returned, or -1 if there is no protocol.
 */
int
proto_get_first_protocol(void **cookie)
{
	protocol_t *protocol;

	if (protocols == NULL)
		return -1;
	*cookie = protocols;
	protocol = protocols->data;
	return protocol->proto_id;
}

int
proto_get_next_protocol(void **cookie)
{
	GList *list_item = *cookie;
	protocol_t *protocol;

	list_item = g_list_next(list_item);
	if (list_item == NULL)
		return -1;
	*cookie = list_item;
	protocol = list_item->data;
	return protocol->proto_id;
}

/*
 * Find the protocol list entry for a protocol given its field ID.
 */
static gint
compare_proto_id(gconstpointer proto_arg, gconstpointer id_arg)
{
	const protocol_t *protocol = proto_arg;
	const int *id_ptr = id_arg;

	return (protocol->proto_id == *id_ptr) ? 0 : 1;
}

static protocol_t *
find_protocol_by_id(int proto_id)
{
	GList *list_entry;
	
	list_entry = g_list_find_custom(protocols, &proto_id, compare_proto_id);
	if (list_entry == NULL)
		return NULL;
	return list_entry->data;
}

static gint compare_filter_name(gconstpointer proto_arg, 
				gconstpointer filter_name)
{
  const protocol_t *protocol = proto_arg;
  const gchar* f_name = filter_name;
  return (strcmp(protocol->filter_name, f_name));
}

int proto_get_id_by_filter_name(gchar* filter_name)
{
  GList *list_entry;
  protocol_t *protocol;
  list_entry = g_list_find_custom(protocols,filter_name,compare_filter_name); 
  if(list_entry == NULL)
    return -1;
  protocol = list_entry->data;
  return(protocol->proto_id);
}

char *
proto_get_protocol_name(int proto_id)
{
	protocol_t *protocol;

	protocol = find_protocol_by_id(proto_id);
	return protocol->name;
}

char *
proto_get_protocol_short_name(int proto_id)
{
	protocol_t *protocol;

	if (proto_id == -1)
		return "(none)";
	protocol = find_protocol_by_id(proto_id);
	return protocol->short_name;
}

char *
proto_get_protocol_filter_name(int proto_id)
{
	protocol_t *protocol;

	protocol = find_protocol_by_id(proto_id);
	return protocol->filter_name;
}

gboolean
proto_is_protocol_enabled(int proto_id)
{
	protocol_t *protocol;

	protocol = find_protocol_by_id(proto_id);
	return protocol->is_enabled;
}

gboolean
proto_can_disable_protocol(int proto_id)
{
	protocol_t *protocol;

	protocol = find_protocol_by_id(proto_id);
	return protocol->can_disable;
}

void 
proto_set_decoding(int proto_id, gboolean enabled)
{
	protocol_t *protocol;

	protocol = find_protocol_by_id(proto_id);
	g_assert(enabled || protocol->can_disable);
	protocol->is_enabled = enabled;
}

void 
proto_set_cant_disable(int proto_id)
{
	protocol_t *protocol;

	protocol = find_protocol_by_id(proto_id);
	protocol->can_disable = FALSE;
}

/* for use with static arrays only, since we don't allocate our own copies
of the header_field_info struct contained withing the hf_register_info struct */
void
proto_register_field_array(int parent, hf_register_info *hf, int num_records)
{
	int			field_id, i;
	hf_register_info	*ptr = hf;
	protocol_t		*proto;

	proto = find_protocol_by_id(parent);
	for (i = 0; i < num_records; i++, ptr++) {
		if (proto != NULL) {
			if (proto->fields == NULL) {
				proto->fields = g_list_append(NULL, ptr);
				proto->last_field = proto->fields;
			} else {
				proto->last_field =
				    g_list_append(proto->last_field, ptr)->next;
			}
		}
		field_id = proto_register_field_init(&ptr->hfinfo, parent);
		*ptr->p_id = field_id;
	}
}

static int
proto_register_field_init(header_field_info *hfinfo, int parent)
{
	/* These types of fields are allowed to have value_strings or true_false_strings */
	g_assert((hfinfo->strings == NULL) || (
			(hfinfo->type == FT_UINT8) ||
			(hfinfo->type == FT_UINT16) ||
			(hfinfo->type == FT_UINT24) ||
			(hfinfo->type == FT_UINT32) ||
			(hfinfo->type == FT_INT8) ||
			(hfinfo->type == FT_INT16) ||
			(hfinfo->type == FT_INT24) ||
			(hfinfo->type == FT_INT32) ||
			(hfinfo->type == FT_BOOLEAN) ));

	/* Require integral types to have a number base */
	switch (hfinfo->type) {

	case FT_UINT8:
	case FT_UINT16:
	case FT_UINT24:
	case FT_UINT32:
	case FT_INT8:
	case FT_INT16:
	case FT_INT24:
	case FT_INT32:
		g_assert(hfinfo->display != BASE_NONE);
		break;

	default:
		break;
	}
	/* if this is a bitfield, compure bitshift */
	if (hfinfo->bitmask) {
		while ((hfinfo->bitmask & (1 << hfinfo->bitshift)) == 0)
			hfinfo->bitshift++;
	}

	hfinfo->parent = parent;
	hfinfo->same_name_next = NULL;
	hfinfo->same_name_prev = NULL;

	/* if we always add and never delete, then id == len - 1 is correct */
	g_ptr_array_add(gpa_hfinfo, hfinfo);
	hfinfo->id = gpa_hfinfo->len - 1;
	return hfinfo->id;
}

void
proto_register_subtree_array(gint **indices, int num_indices)
{
	int	i;
	gint	**ptr = indices;

	/*
	 * Add "num_indices" elements to "tree_is_expanded".
	 */
	tree_is_expanded = g_realloc(tree_is_expanded,
	    (num_tree_types + num_indices)*sizeof (gint));

	/*
	 * Assign "num_indices" subtree numbers starting at "num_tree_types",
	 * returning the indices through the pointers in the array whose
	 * first element is pointed to by "indices", set to FALSE the
	 * elements to which those subtree numbers refer, and update
	 * "num_tree_types" appropriately.
	 */
	for (i = 0; i < num_indices; i++, ptr++, num_tree_types++) {
		tree_is_expanded[num_tree_types] = FALSE;
		**ptr = num_tree_types;
	}
}

void
proto_item_fill_label(field_info *fi, gchar *label_str)
{
	header_field_info		*hfinfo = fi->hfinfo;

	guint8				*bytes;
	guint32				integer;
	ipv4_addr			*ipv4;
	guint32				n_addr; /* network-order IPv4 address */

	switch(hfinfo->type) {
		case FT_NONE:
		case FT_PROTOCOL:
			snprintf(label_str, ITEM_LABEL_LENGTH,
				"%s", hfinfo->name);
			break;

		case FT_BOOLEAN:
			fill_label_boolean(fi, label_str);
			break;

		case FT_BYTES:
		case FT_UINT_BYTES:
			bytes = fvalue_get(fi->value);
			if (bytes) {
				snprintf(label_str, ITEM_LABEL_LENGTH,
					"%s: %s", hfinfo->name, 
					 bytes_to_str(bytes, fvalue_length(fi->value)));
			}
			else {
				snprintf(label_str, ITEM_LABEL_LENGTH,
					"%s: <MISSING>", hfinfo->name);
			}
			break;

		/* Four types of integers to take care of:
		 * 	Bitfield, with val_string
		 * 	Bitfield, w/o val_string
		 * 	Non-bitfield, with val_string
		 * 	Non-bitfield, w/o val_string
		 */
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
			if (hfinfo->bitmask) {
				if (hfinfo->strings) {
					fill_label_enumerated_bitfield(fi, label_str);
				}
				else {
					fill_label_numeric_bitfield(fi, label_str);
				}
			}
			else {
				if (hfinfo->strings) {
					fill_label_enumerated_uint(fi, label_str);
				}
				else {
					fill_label_uint(fi, label_str);
				}
			}
			break;

		case FT_UINT64:
			fill_label_uint64(fi, label_str);
			break;

		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			g_assert(!hfinfo->bitmask);
			if (hfinfo->strings) {
				fill_label_enumerated_int(fi, label_str);
			}
			else {
				fill_label_int(fi, label_str);
			}
			break;

		case FT_INT64:
			fill_label_int64(fi, label_str);
			break;

		case FT_DOUBLE:
			snprintf(label_str, ITEM_LABEL_LENGTH,
				"%s: %g", hfinfo->name, fvalue_get_floating(fi->value));
			break;

		case FT_ABSOLUTE_TIME:
			snprintf(label_str, ITEM_LABEL_LENGTH,
				"%s: %s", hfinfo->name,
				abs_time_to_str(fvalue_get(fi->value)));
			break;

		case FT_RELATIVE_TIME:
			snprintf(label_str, ITEM_LABEL_LENGTH,
				"%s: %s seconds", hfinfo->name,
				rel_time_to_secs_str(fvalue_get(fi->value)));
			break;

		case FT_IPXNET:
			integer = fvalue_get_integer(fi->value);
			snprintf(label_str, ITEM_LABEL_LENGTH,
				"%s: 0x%08X (%s)", hfinfo->name,
				integer, get_ipxnet_name(integer));
			break;

		case FT_ETHER:
			bytes = fvalue_get(fi->value);
			snprintf(label_str, ITEM_LABEL_LENGTH,
				"%s: %s (%s)", hfinfo->name,
				ether_to_str(bytes),
				get_ether_name(bytes));
			break;

		case FT_IPv4:
			ipv4 = fvalue_get(fi->value);
			n_addr = ipv4_get_net_order_addr(ipv4);
			snprintf(label_str, ITEM_LABEL_LENGTH,
				"%s: %s (%s)", hfinfo->name,
				get_hostname(n_addr),
				ip_to_str((guint8*)&n_addr));
			break;

		case FT_IPv6:
			bytes = fvalue_get(fi->value);
			snprintf(label_str, ITEM_LABEL_LENGTH,
				"%s: %s (%s)", hfinfo->name,
				get_hostname6((struct e_in6_addr *)bytes),
				ip6_to_str((struct e_in6_addr*)bytes));
			break;
	
		case FT_STRING:
		case FT_STRINGZ:
		case FT_UINT_STRING:
			snprintf(label_str, ITEM_LABEL_LENGTH,
				"%s: %s", hfinfo->name, (char*) fvalue_get(fi->value));
			break;

		default:
			g_error("hfinfo->type %d (%s) not handled\n",
					hfinfo->type,
					ftype_name(hfinfo->type));
			g_assert_not_reached();
			break;
	}
}

static void
fill_label_uint64(field_info *fi, gchar *label_str)
{
	unsigned char *bytes;
	header_field_info *hfinfo = fi->hfinfo;

	bytes=fvalue_get(fi->value);
	switch(hfinfo->display){
	case BASE_DEC:
		snprintf(label_str, ITEM_LABEL_LENGTH,
			"%s: %s", hfinfo->name,
			u64toa(bytes));
		break;
	case BASE_HEX:
		snprintf(label_str, ITEM_LABEL_LENGTH,
			"%s: %s", hfinfo->name,
			u64toh(bytes));
		break;
	default:
		g_assert_not_reached();
		;
	}
}

static void
fill_label_int64(field_info *fi, gchar *label_str)
{
	unsigned char *bytes;
	header_field_info *hfinfo = fi->hfinfo;

	bytes=fvalue_get(fi->value);
	switch(hfinfo->display){
	case BASE_DEC:
		snprintf(label_str, ITEM_LABEL_LENGTH,
			"%s: %s", hfinfo->name,
			i64toa(bytes));
		break;
	case BASE_HEX:
		snprintf(label_str, ITEM_LABEL_LENGTH,
			"%s: %s", hfinfo->name,
			u64toh(bytes));
		break;
	default:
		g_assert_not_reached();
		;
	}
}

static void
fill_label_boolean(field_info *fi, gchar *label_str)
{
	char	*p = label_str;
	int	bitfield_byte_length = 0, bitwidth;
	guint32	unshifted_value;
	guint32	value;

	header_field_info		*hfinfo = fi->hfinfo;
	static true_false_string	default_tf = { "True", "False" };
	true_false_string		*tfstring = &default_tf;

	if (hfinfo->strings) {
		tfstring = (struct true_false_string*) hfinfo->strings;
	}

	value = fvalue_get_integer(fi->value);
	if (hfinfo->bitmask) {
		/* Figure out the bit width */
		bitwidth = hfinfo_bitwidth(hfinfo);

		/* Un-shift bits */
		unshifted_value = value;
		if (hfinfo->bitshift > 0) {
			unshifted_value <<= hfinfo->bitshift;
		}

		/* Create the bitfield first */
		p = decode_bitfield_value(label_str, unshifted_value, hfinfo->bitmask, bitwidth);
		bitfield_byte_length = p - label_str;
	}

	/* Fill in the textual info */
	snprintf(p, ITEM_LABEL_LENGTH - bitfield_byte_length,
		"%s: %s",  hfinfo->name,
		value ? tfstring->true_string : tfstring->false_string);
}


/* Fills data for bitfield ints with val_strings */
static void
fill_label_enumerated_bitfield(field_info *fi, gchar *label_str)
{
	char *format = NULL, *p;
	int bitfield_byte_length, bitwidth;
	guint32 unshifted_value;
	guint32 value;

	header_field_info	*hfinfo = fi->hfinfo;

	/* Figure out the bit width */
	bitwidth = hfinfo_bitwidth(hfinfo);

	/* Pick the proper format string */
	format = hfinfo_uint_vals_format(hfinfo);

	/* Un-shift bits */
	unshifted_value = fvalue_get_integer(fi->value);
	value = unshifted_value;
	if (hfinfo->bitshift > 0) {
		unshifted_value <<= hfinfo->bitshift;
	}

	/* Create the bitfield first */
	p = decode_bitfield_value(label_str, unshifted_value, hfinfo->bitmask, bitwidth);
	bitfield_byte_length = p - label_str;

	/* Fill in the textual info using stored (shifted) value */
	snprintf(p, ITEM_LABEL_LENGTH - bitfield_byte_length,
			format,  hfinfo->name,
			val_to_str(value, cVALS(hfinfo->strings), "Unknown"), value);
}

static void
fill_label_numeric_bitfield(field_info *fi, gchar *label_str)
{
	char *format = NULL, *p;
	int bitfield_byte_length, bitwidth;
	guint32 unshifted_value;
	guint32 value;

	header_field_info	*hfinfo = fi->hfinfo;

	/* Figure out the bit width */
	bitwidth = hfinfo_bitwidth(hfinfo);

	/* Pick the proper format string */
	format = hfinfo_uint_format(hfinfo);

	/* Un-shift bits */
	unshifted_value = fvalue_get_integer(fi->value);
	value = unshifted_value;
	if (hfinfo->bitshift > 0) {
		unshifted_value <<= hfinfo->bitshift;
	}

	/* Create the bitfield using */
	p = decode_bitfield_value(label_str, unshifted_value, hfinfo->bitmask, bitwidth);
	bitfield_byte_length = p - label_str;

	/* Fill in the textual info using stored (shifted) value */
	snprintf(p, ITEM_LABEL_LENGTH - bitfield_byte_length,
			format,  hfinfo->name, value);
}

static void
fill_label_enumerated_uint(field_info *fi, gchar *label_str)
{
	char *format = NULL;
	header_field_info	*hfinfo = fi->hfinfo;
	guint32 value;

	/* Pick the proper format string */
	format = hfinfo_uint_vals_format(hfinfo);

	value = fvalue_get_integer(fi->value);

	/* Fill in the textual info */
	snprintf(label_str, ITEM_LABEL_LENGTH,
			format,  hfinfo->name,
			val_to_str(value, cVALS(hfinfo->strings), "Unknown"), value);
}

static void
fill_label_uint(field_info *fi, gchar *label_str)
{
	char *format = NULL;
	header_field_info	*hfinfo = fi->hfinfo;
	guint32 value;

	/* Pick the proper format string */
	format = hfinfo_uint_format(hfinfo);
	value = fvalue_get_integer(fi->value);

	/* Fill in the textual info */
	snprintf(label_str, ITEM_LABEL_LENGTH,
			format,  hfinfo->name, value);
}

static void
fill_label_enumerated_int(field_info *fi, gchar *label_str)
{
	char *format = NULL;
	header_field_info	*hfinfo = fi->hfinfo;
	guint32 value;

	/* Pick the proper format string */
	format = hfinfo_int_vals_format(hfinfo);
	value = fvalue_get_integer(fi->value);

	/* Fill in the textual info */
	snprintf(label_str, ITEM_LABEL_LENGTH,
			format,  hfinfo->name,
			val_to_str(value, cVALS(hfinfo->strings), "Unknown"), value);
}

static void
fill_label_int(field_info *fi, gchar *label_str)
{
	char *format = NULL;
	header_field_info	*hfinfo = fi->hfinfo;
	guint32 value;

	/* Pick the proper format string */
	format = hfinfo_int_format(hfinfo);
	value = fvalue_get_integer(fi->value);

	/* Fill in the textual info */
	snprintf(label_str, ITEM_LABEL_LENGTH,
			format,  hfinfo->name, value);
}

int
hfinfo_bitwidth(header_field_info *hfinfo)
{
	int bitwidth = 0;

	if (!hfinfo->bitmask) {
		return 0;
	}

	switch(hfinfo->type) {
		case FT_UINT8:
		case FT_INT8:
			bitwidth = 8;
			break;
		case FT_UINT16:
		case FT_INT16:
			bitwidth = 16;
			break;
		case FT_UINT24:
		case FT_INT24:
			bitwidth = 24;
			break;
		case FT_UINT32:
		case FT_INT32:
			bitwidth = 32;
			break;
		case FT_BOOLEAN:
			bitwidth = hfinfo->display; /* hacky? :) */
			break;
		default:
			g_assert_not_reached();
			;
	}
	return bitwidth;
}

static char*
hfinfo_uint_vals_format(header_field_info *hfinfo)
{
	char *format = NULL;

	switch(hfinfo->display) {
		case BASE_DEC:
		case BASE_BIN: /* I'm lazy */
			format = "%s: %s (%u)";
			break;
		case BASE_OCT: /* I'm lazy */
			format = "%s: %s (%o)";
			break;
		case BASE_HEX:
			switch(hfinfo->type) {
				case FT_UINT8:
					format = "%s: %s (0x%02x)";
					break;
				case FT_UINT16:
					format = "%s: %s (0x%04x)";
					break;
				case FT_UINT24:
					format = "%s: %s (0x%06x)";
					break;
				case FT_UINT32:
					format = "%s: %s (0x%08x)";
					break;
				default:
					g_assert_not_reached();
					;
			}
			break;
		default:
			g_assert_not_reached();
			;
	}
	return format;
}

static char*
hfinfo_uint_format(header_field_info *hfinfo)
{
	char *format = NULL;

	/* Pick the proper format string */
	switch(hfinfo->display) {
		case BASE_DEC:
		case BASE_BIN: /* I'm lazy */
			format = "%s: %u";
			break;
		case BASE_OCT: /* I'm lazy */
			format = "%s: %o";
			break;
		case BASE_HEX:
			switch(hfinfo->type) {
				case FT_UINT8:
					format = "%s: 0x%02x";
					break;
				case FT_UINT16:
					format = "%s: 0x%04x";
					break;
				case FT_UINT24:
					format = "%s: 0x%06x";
					break;
				case FT_UINT32:
					format = "%s: 0x%08x";
					break;
				default:
					g_assert_not_reached();
					;
			}
			break;
		default:
			g_assert_not_reached();
			;
	}
	return format;
}

static char*
hfinfo_int_vals_format(header_field_info *hfinfo)
{
	char *format = NULL;

	switch(hfinfo->display) {
		case BASE_DEC:
		case BASE_BIN: /* I'm lazy */
			format = "%s: %s (%d)";
			break;
		case BASE_OCT: /* I'm lazy */
			format = "%s: %s (%o)";
			break;
		case BASE_HEX:
			switch(hfinfo->type) {
				case FT_INT8:
					format = "%s: %s (0x%02x)";
					break;
				case FT_INT16:
					format = "%s: %s (0x%04x)";
					break;
				case FT_INT24:
					format = "%s: %s (0x%06x)";
					break;
				case FT_INT32:
					format = "%s: %s (0x%08x)";
					break;
				default:
					g_assert_not_reached();
					;
			}
			break;
		default:
			g_assert_not_reached();
			;
	}
	return format;
}

static char*
hfinfo_int_format(header_field_info *hfinfo)
{
	char *format = NULL;

	/* Pick the proper format string */
	switch(hfinfo->display) {
		case BASE_DEC:
		case BASE_BIN: /* I'm lazy */
			format = "%s: %d";
			break;
		case BASE_OCT: /* I'm lazy */
			format = "%s: %o";
			break;
		case BASE_HEX:
			switch(hfinfo->type) {
				case FT_INT8:
					format = "%s: 0x%02x";
					break;
				case FT_INT16:
					format = "%s: 0x%04x";
					break;
				case FT_INT24:
					format = "%s: 0x%06x";
					break;
				case FT_INT32:
					format = "%s: 0x%08x";
					break;
				default:
					g_assert_not_reached();
					;
			}
			break;
		default:
			g_assert_not_reached();
			;
	}
	return format;
}



int
proto_registrar_n(void)
{
	return gpa_hfinfo->len;
}

char*
proto_registrar_get_name(int n)
{
	header_field_info *hfinfo;

	hfinfo = proto_registrar_get_nth(n);
	if (hfinfo)
		return hfinfo->name;
	else
		return NULL;
}

char*
proto_registrar_get_abbrev(int n)
{
	header_field_info *hfinfo;

	hfinfo = proto_registrar_get_nth(n);
	if (hfinfo)
		return hfinfo->abbrev;
	else
		return NULL;
}

int
proto_registrar_get_ftype(int n)
{
	header_field_info *hfinfo;

	hfinfo = proto_registrar_get_nth(n);
	if (hfinfo)
		return hfinfo->type;
	else
		return -1;
}

int
proto_registrar_get_parent(int n)
{
	header_field_info *hfinfo;

	hfinfo = proto_registrar_get_nth(n);
	if (hfinfo)
		return hfinfo->parent;
	else
		return -2;
}

gboolean
proto_registrar_is_protocol(int n)
{
	header_field_info *hfinfo;

	hfinfo = proto_registrar_get_nth(n);
	if (hfinfo)
		return (hfinfo->parent == -1 ? TRUE : FALSE);
	else
		return FALSE;
}

/* Returns length of field in packet (not necessarily the length
 * in our internal representation, as in the case of IPv4).
 * 0 means undeterminable at time of registration
 * -1 means the field is not registered. */
gint
proto_registrar_get_length(int n)
{
	header_field_info *hfinfo;

	hfinfo = proto_registrar_get_nth(n);
	if (!hfinfo)
		return -1;

	return ftype_length(hfinfo->type);
}


/* =================================================================== */
/* used when calling proto search functions */
typedef struct {
	header_field_info	*target;
	const guint8		*packet_data;
	guint			packet_len;
	gboolean		halt_on_first_hit;
	GNodeTraverseFunc	traverse_func; /* for traverse_subtree_for_field() */
	union {
		GPtrArray		*ptr_array;
		GNode			*node;
	} 			result;
} proto_tree_search_info;

/* Looks for a protocol at the top layer of the tree. The protocol can occur
 * more than once, for those encapsulated protocols. For each protocol subtree
 * that is found, the callback function is called.
 */
static void
proto_find_protocol_multi(proto_tree* tree, GNodeTraverseFunc callback,
			proto_tree_search_info *sinfo)
{
	g_assert(callback != NULL);
	g_node_traverse((GNode*)tree, G_IN_ORDER, G_TRAVERSE_ALL, 2, callback, (gpointer*)sinfo);
}

/* Calls a traversal function for all subtrees.
 */
static gboolean
traverse_subtree_for_field(GNode *node, gpointer data)
{
	field_info *fi = PITEM_FINFO(node);
	proto_tree_search_info	*sinfo = (proto_tree_search_info*) data;

	if (fi) { /* !fi == the top most container node which holds nothing */
			g_node_traverse(node, G_IN_ORDER, G_TRAVERSE_ALL, -1,
					sinfo->traverse_func, sinfo);
			if (sinfo->result.node)
				return sinfo->halt_on_first_hit; /* halt? continue? */
	}
	return FALSE; /* keep traversing */
}

/* Looks for a protocol or a field in a proto_tree. Returns TRUE if
 * it exists anywhere, or FALSE if it exists nowhere. */
gboolean
proto_check_for_protocol_or_field(proto_tree* tree, int id)
{
    GPtrArray *ptrs = proto_get_finfo_ptr_array(tree, id);

    if (!ptrs) {
        return FALSE;
    }
    else if (g_ptr_array_len(ptrs) > 0) {
        return TRUE;
    }
    else {
        return FALSE;
    }
}

/* Return GPtrArray* of field_info pointers for all hfindex that appear in tree.
 * This only works if the hfindex was "primed" before the dissection
 * took place, as we just pass back the already-created GPtrArray*.
 * The caller should *not* free the GPtrArray*; proto_tree_free_node()
 * handles that. */
GPtrArray*
proto_get_finfo_ptr_array(proto_tree *tree, int id)
{
    return g_hash_table_lookup(PTREE_DATA(tree)->interesting_hfids,
            GINT_TO_POINTER(id));
}


typedef struct {
	guint		offset;
	field_info	*finfo;
	gchar 		*name;
} offset_search_t;

static gboolean
check_for_offset(GNode *node, gpointer data)
{
	field_info          *fi = PITEM_FINFO(node);
	offset_search_t		*offsearch = data;

	/* !fi == the top most container node which holds nothing */
	if (fi && fi->visible && fi->ds_name &&
	    strcmp(offsearch->name, fi->ds_name) == 0) {
		if (offsearch->offset >= (guint) fi->start &&
				offsearch->offset < (guint) (fi->start + fi->length)) {

			offsearch->finfo = fi;
			return FALSE; /* keep traversing */
		}
	}
	return FALSE; /* keep traversing */
}

/* Search a proto_tree backwards (from leaves to root) looking for the field
 * whose start/length occupies 'offset' */
/* XXX - I couldn't find an easy way to search backwards, so I search
 * forwards, w/o stopping. Therefore, the last finfo I find will the be
 * the one I want to return to the user. This algorithm is inefficient
 * and could be re-done, but I'd have to handle all the children and
 * siblings of each node myself. When I have more time I'll do that.
 * (yeah right) */
field_info*
proto_find_field_from_offset(proto_tree *tree, guint offset, char* ds_name)
{
	offset_search_t		offsearch;

	offsearch.offset = offset;
	offsearch.finfo = NULL;
	offsearch.name = ds_name;

	g_node_traverse((GNode*)tree, G_PRE_ORDER, G_TRAVERSE_ALL, -1,
			check_for_offset, &offsearch);

	return offsearch.finfo;
}



	

/* Dumps the contents of the registration database to stdout. An indepedent program can take
 * this output and format it into nice tables or HTML or whatever.
 *
 * There is one record per line. Each record is either a protocol or a header
 * field, differentiated by the first field. The fields are tab-delimited.
 *
 * Protocols
 * ---------
 * Field 1 = 'P'
 * Field 2 = protocol name
 * Field 3 = protocol abbreviation
 *
 * Header Fields
 * -------------
 * Field 1 = 'F'
 * Field 2 = field name
 * Field 3 = field abbreviation
 * Field 4 = type ( textual representation of the the ftenum type )
 * Field 5 = parent protocol abbreviation
 */
void
proto_registrar_dump(void)
{
	header_field_info	*hfinfo, *parent_hfinfo;
	int			i, len;
	const char 		*enum_name;

	len = gpa_hfinfo->len;
	for (i = 0; i < len ; i++) {
		hfinfo = proto_registrar_get_nth(i);

		/*
		 * Skip fields with zero-length names or abbreviations;
		 * the pseudo-field for "proto_tree_add_text()" is such
		 * a field, and we don't want it in the list of filterable
		 * fields.
		 *
		 *
		 * XXX - perhaps the name and abbrev field should be null
		 * pointers rather than null strings for that pseudo-field,
		 * but we'd have to add checks for null pointers in some
		 * places if we did that.
		 *
		 * Or perhaps protocol tree items added with
		 * "proto_tree_add_text()" should have -1 as the field index,
		 * with no pseudo-field being used, but that might also
		 * require special checks for -1 to be added.
		 */
		if (strlen(hfinfo->name) == 0 || strlen(hfinfo->abbrev) == 0)
			continue;

		/* format for protocols */
		if (proto_registrar_is_protocol(i)) {
			printf("P\t%s\t%s\n", hfinfo->name, hfinfo->abbrev);
		}
		/* format for header fields */
		else {
			/*
			 * If this field isn't at the head of the list of
			 * fields with this name, skip this field - all
			 * fields with the same name are really just versions
			 * of the same field stored in different bits, and
			 * should have the same type/radix/value list, and
			 * just differ in their bit masks.  (If a field isn't
			 * a bitfield, but can be, say, 1 or 2 bytes long,
			 * it can just be made FT_UINT16, meaning the
			 * *maximum* length is 2 bytes, and be used
			 * for all lengths.)
			 */
			if (hfinfo->same_name_prev != NULL)
				continue;

			parent_hfinfo = proto_registrar_get_nth(hfinfo->parent);
			g_assert(parent_hfinfo);

			enum_name = ftype_name(hfinfo->type);
			printf("F\t%s\t%s\t%s\t%s\n", hfinfo->name, hfinfo->abbrev,
				enum_name,parent_hfinfo->abbrev);
		}
	}
}

static char*
hfinfo_numeric_format(header_field_info *hfinfo)
{
	char *format = NULL;

	/* Pick the proper format string */
	switch(hfinfo->display) {
		case BASE_DEC:
		case BASE_OCT: /* I'm lazy */
		case BASE_BIN: /* I'm lazy */
			switch(hfinfo->type) {
				case FT_UINT8:
				case FT_UINT16:
				case FT_UINT24:
				case FT_UINT32:
					format = "%s == %u";
					break;
				case FT_INT8:
				case FT_INT16:
				case FT_INT24:
				case FT_INT32:
					format = "%s == %d";
					break;
				default:
					g_assert_not_reached();
					;
			}
			break;
		case BASE_HEX:
			switch(hfinfo->type) {
				case FT_UINT8:
					format = "%s == 0x%02x";
					break;
				case FT_UINT16:
					format = "%s == 0x%04x";
					break;
				case FT_UINT24:
					format = "%s == 0x%06x";
					break;
				case FT_UINT32:
					format = "%s == 0x%08x";
					break;
				default:
					g_assert_not_reached();
					;
			}
			break;
		default:
			g_assert_not_reached();
			;
	}
	return format;
}

/*
 * Returns TRUE if we can do a "match selected" on the field, FALSE
 * otherwise.
 */
gboolean
proto_can_match_selected(field_info *finfo)
{
	header_field_info	*hfinfo;

	hfinfo = finfo->hfinfo;
	g_assert(hfinfo);

	switch(hfinfo->type) {

		case FT_BOOLEAN:
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_UINT64:
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
		case FT_INT64:
		case FT_IPv4:
		case FT_IPXNET:
		case FT_IPv6:
		case FT_DOUBLE:
		case FT_ETHER:
		case FT_ABSOLUTE_TIME:
		case FT_RELATIVE_TIME:
		case FT_STRING:
		case FT_STRINGZ:
		case FT_UINT_STRING:
		case FT_BYTES:
		case FT_UINT_BYTES:
			/*
			 * These all have values, so we can match.
			 */
			return TRUE;

		default:
			/*
			 * This doesn't have a value, so we'd match
			 * on the raw bytes at this address;
			 * however, if the length is 0, there's nothing
			 * to match, so we can't match.
			 */
			return (finfo->length != 0);
	}
}

char*
proto_alloc_dfilter_string(field_info *finfo, guint8 *pd)
{
	header_field_info	*hfinfo;
	int			abbrev_len;
	char			*buf, *stringified, *format, *ptr, *value_str;
	int			dfilter_len, i;
	guint8			*c;

	hfinfo = finfo->hfinfo;
	g_assert(hfinfo);
	abbrev_len = strlen(hfinfo->abbrev);

	switch(hfinfo->type) {

		case FT_BOOLEAN:
			dfilter_len = abbrev_len + 6;
			buf = g_malloc0(dfilter_len);
			snprintf(buf, dfilter_len, "%s == %s",
					hfinfo->abbrev,
					fvalue_get_integer(finfo->value) ? "1" : "0");
			break;

		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			dfilter_len = abbrev_len + 20;
			buf = g_malloc0(dfilter_len);
			format = hfinfo_numeric_format(hfinfo);
			snprintf(buf, dfilter_len, format, hfinfo->abbrev, fvalue_get_integer(finfo->value));
			break;

		case FT_UINT64:
			stringified = u64toa(fvalue_get(finfo->value));
			dfilter_len = abbrev_len + 4 + strlen(stringified) +1;
			buf = g_malloc0(dfilter_len);
			snprintf(buf, dfilter_len, "%s == %s", hfinfo->abbrev,
					stringified);
			break;

		case FT_INT64:
			stringified = i64toa(fvalue_get(finfo->value));
			dfilter_len = abbrev_len + 4 + strlen(stringified) +1;
			buf = g_malloc0(dfilter_len);
			snprintf(buf, dfilter_len, "%s == %s", hfinfo->abbrev,
					stringified);
			break;

		case FT_IPv4:
			dfilter_len = abbrev_len + 4 + 15 + 1;
			buf = g_malloc0(dfilter_len);
			snprintf(buf, dfilter_len, "%s == %s", hfinfo->abbrev,
					ipv4_addr_str(fvalue_get(finfo->value)));
			break;

		case FT_IPXNET:
			dfilter_len = abbrev_len + 15;
			buf = g_malloc0(dfilter_len);
			snprintf(buf, dfilter_len, "%s == 0x%08x", hfinfo->abbrev,
					fvalue_get_integer(finfo->value));
			break;

		case FT_IPv6:
			stringified = ip6_to_str((struct e_in6_addr*) fvalue_get(finfo->value));
			dfilter_len = abbrev_len + 4 + strlen(stringified) + 1;
			buf = g_malloc0(dfilter_len);
			snprintf(buf, dfilter_len, "%s == %s", hfinfo->abbrev,
					stringified);
			break;

		case FT_DOUBLE:
			dfilter_len = abbrev_len + 30;
			buf = g_malloc0(dfilter_len);
			snprintf(buf, dfilter_len, "%s == %f", hfinfo->abbrev,
					fvalue_get_floating(finfo->value));
			break;

		case FT_ETHER:
			dfilter_len = abbrev_len + 22;
			buf = g_malloc0(dfilter_len);
			snprintf(buf, dfilter_len, "%s == %s",
					hfinfo->abbrev,
					ether_to_str(fvalue_get(finfo->value)));
			break;

		case FT_ABSOLUTE_TIME:
			value_str =
			    abs_time_to_str((nstime_t *)fvalue_get(finfo->value));
			dfilter_len = abbrev_len + strlen(value_str) + 7;
			buf = g_malloc0(dfilter_len);
			snprintf(buf, dfilter_len, "%s == \"%s\"",
					hfinfo->abbrev, value_str);
			break;

		case FT_RELATIVE_TIME:
			value_str =
			    rel_time_to_secs_str((nstime_t *)fvalue_get(finfo->value));
			dfilter_len = abbrev_len + strlen(value_str) + 4;
			buf = g_malloc0(dfilter_len);
			snprintf(buf, dfilter_len, "%s == %s",
					hfinfo->abbrev, value_str);
			break;


		case FT_STRING:
			value_str = fvalue_get(finfo->value);
			dfilter_len = abbrev_len + strlen(value_str) + 7;
			buf = g_malloc0(dfilter_len);
			snprintf(buf, dfilter_len, "%s == \"%s\"",
				 hfinfo->abbrev, value_str);
			break;

		case FT_BYTES:
		case FT_UINT_BYTES:
			dfilter_len = fvalue_length(finfo->value)*3 - 1;
			dfilter_len += abbrev_len + 7;
			buf = g_malloc0(dfilter_len);
			snprintf(buf, dfilter_len, "%s == %s",
				 hfinfo->abbrev,
				 /* XXX - bytes_to_str_punct() will truncate long strings with '...' */
				 bytes_to_str_punct(fvalue_get(finfo->value),
					 fvalue_length(finfo->value),':'));
			break;       

		default:
			c = pd + finfo->start;
			buf = g_malloc0(32 + finfo->length * 3);
			ptr = buf;

			sprintf(ptr, "frame[%d] == ", finfo->start);
			ptr = buf+strlen(buf);

			for (i=0;i<finfo->length; i++) {
				if (i == 0 ) {
					sprintf(ptr, "%02x", *c++);
				}
				else {
					sprintf(ptr, ":%02x", *c++);
				}
				ptr = buf+strlen(buf);
			}
			break;
	}

	return buf;
}
