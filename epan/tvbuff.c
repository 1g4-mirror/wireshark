/* tvbuff.c
 *
 * Testy, Virtual(-izable) Buffer of guint8*'s
 * 
 * "Testy" -- the buffer gets mad when an attempt to access data
 * 		beyond the bounds of the buffer. An exception is thrown.
 *
 * "Virtual" -- the buffer can have its own data, can use a subset of
 * 		the data of a backing tvbuff, or can be a composite of
 * 		other tvbuffs.
 *
 * $Id: tvbuff.c,v 1.29.2.1 2002/03/06 22:38:43 gram Exp $
 *
 * Copyright (c) 2000 by Gilbert Ramirez <gram@alumni.rice.edu>
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

#include <string.h>

#include "pint.h"
#include "tvbuff.h"
#include "strutil.h"

typedef struct {
	/* The backing tvbuff_t */
	tvbuff_t	*tvb;

	/* The offset/length of 'tvb' to which I'm privy */
	guint		offset;
	guint		length;

} tvb_backing_t;

typedef struct {
	GSList		*tvbs;

	/* Used for quick testing to see if this
	 * is the tvbuff that a COMPOSITE is
	 * interested in. */
	guint		*start_offsets;
	guint		*end_offsets;

} tvb_comp_t;

struct tvbuff {
	/* Record-keeping */
	tvbuff_type		type;
	gboolean		initialized;
	guint			usage_count;
	gchar*			ds_name;	  /* data source name */

	/* The tvbuffs in which this tvbuff is a member
	 * (that is, a backing tvbuff for a TVBUFF_SUBSET
	 * or a member for a TVB_COMPOSITE) */
	GSList			*used_in;

	/* TVBUFF_SUBSET and TVBUFF_COMPOSITE keep track
	 * of the other tvbuff's they use */
	union {
		tvb_backing_t	subset;
		tvb_comp_t	composite;
	} tvbuffs;

	/* We're either a TVBUFF_REAL_DATA or a
	 * TVBUFF_SUBSET that has a backing buffer that
	 * has real_data != NULL, or a TVBUFF_COMPOSITE
	 * which has flattened its data due to a call
	 * to tvb_get_ptr().
	 */
	guint8			*real_data;

	/* Length of virtual buffer (and/or real_data). */
	guint			length;

	/* Reported length. */
	guint			reported_length;

	/* Offset from beginning of first TVBUFF_REAL. */
	gint			raw_offset;

	/* Func to call when actually freed */
	tvbuff_free_cb_t	free_cb;
};

static guint8*
ensure_contiguous(tvbuff_t *tvb, gint offset, gint length);

/* We dole out tvbuff's from this memchunk. */
GMemChunk *tvbuff_mem_chunk = NULL;

void
tvbuff_init(void)
{
	if (!tvbuff_mem_chunk)
		tvbuff_mem_chunk = g_mem_chunk_create(tvbuff_t, 20, G_ALLOC_AND_FREE);
}

void
tvbuff_cleanup(void)
{
	if (tvbuff_mem_chunk)
		g_mem_chunk_destroy(tvbuff_mem_chunk);

	tvbuff_mem_chunk = NULL;
}




static void
tvb_init(tvbuff_t *tvb, tvbuff_type type)
{
	tvb_backing_t	*backing;
	tvb_comp_t	*composite;

	tvb->type		= type;
	tvb->initialized	= FALSE;
	tvb->usage_count	= 1;
	tvb->length		= 0;
	tvb->reported_length	= 0;
	tvb->free_cb		= NULL;
	tvb->real_data		= NULL;
	tvb->raw_offset		= -1;
	tvb->used_in		= NULL;
	tvb->ds_name		= NULL;

	switch(type) {
		case TVBUFF_REAL_DATA:
			/* Nothing */
			break;

		case TVBUFF_SUBSET:
			backing = &tvb->tvbuffs.subset;
			backing->tvb	= NULL;
			backing->offset	= 0;
			backing->length	= 0;
			break;

		case TVBUFF_COMPOSITE:
			composite = &tvb->tvbuffs.composite;
			composite->tvbs			= NULL;
			composite->start_offsets	= NULL;
			composite->end_offsets		= NULL;
			break;
	}
}


tvbuff_t*
tvb_new(tvbuff_type type)
{
	tvbuff_t	*tvb;

	tvb = g_chunk_new(tvbuff_t, tvbuff_mem_chunk);
	g_assert(tvb);

	tvb_init(tvb, type);

	return tvb;
}

/* We accept a void* instead of a field_info* to satisfy CLEANUP_POP */
static void
tvb_free_void(void *tvb)
{
	tvb_free((tvbuff_t*)tvb);
}



void
tvb_free(tvbuff_t* tvb)
{
	tvbuff_t	*member_tvb;
	tvb_comp_t	*composite;
	GSList		*slist;

	tvb->usage_count--;

	if (tvb->usage_count == 0) {
		switch (tvb->type) {
		case TVBUFF_REAL_DATA:
			if (tvb->free_cb) {
				tvb->free_cb(tvb->real_data);
			}
			if (tvb->ds_name)
				g_free(tvb->ds_name);
			break;

		case TVBUFF_SUBSET:
			/* This will be NULL if tvb_new_subset() fails because
			 * reported_length < -1 */
			if (tvb->tvbuffs.subset.tvb) {
				tvb_decrement_usage_count(tvb->tvbuffs.subset.tvb, 1);
			}

			/*
			 * TVBUFF_SUBSET tvbuffs share a "ds_name" with
			 * the parent tvbuff, so this tvbuff's "ds_name"
			 * shouldn't be freed.
			 */
			break;

		case TVBUFF_COMPOSITE:
			composite = &tvb->tvbuffs.composite;
			for (slist = composite->tvbs; slist != NULL ; slist = slist->next) {
				member_tvb = slist->data;
				tvb_decrement_usage_count(member_tvb, 1);
			}

			g_slist_free(composite->tvbs);

			if (composite->start_offsets)
				g_free(composite->start_offsets);
			if (composite->end_offsets)
				g_free(composite->end_offsets);
			if (tvb->real_data)
				g_free(tvb->real_data);
			if (tvb->ds_name)
				g_free(tvb->ds_name);

			break;
		}

		if (tvb->used_in) {
			g_slist_free(tvb->used_in);
		}

		g_chunk_free(tvb, tvbuff_mem_chunk);
	}
}

guint
tvb_increment_usage_count(tvbuff_t* tvb, guint count)
{
	tvb->usage_count += count;

	return tvb->usage_count;
}

guint
tvb_decrement_usage_count(tvbuff_t* tvb, guint count)
{
	if (tvb->usage_count <= count) {
		tvb->usage_count = 1;
		tvb_free(tvb);
		return 0;
	}
	else {
		tvb->usage_count -= count;
		return tvb->usage_count;
	}

}

void
tvb_free_chain(tvbuff_t* tvb)
{
	GSList		*slist;

	/* Recursively call tvb_free_chain() */
	for (slist = tvb->used_in; slist != NULL ; slist = slist->next) {
		tvb_free_chain( (tvbuff_t*)slist->data );
	}

	/* Stop the recursion */
	tvb_free(tvb);
}



void
tvb_set_free_cb(tvbuff_t* tvb, tvbuff_free_cb_t func)
{
	g_assert(tvb->type == TVBUFF_REAL_DATA);
	tvb->free_cb = func;
}

static void
add_to_used_in_list(tvbuff_t *tvb, tvbuff_t *used_in)
{
	tvb->used_in = g_slist_prepend(tvb->used_in, used_in);
	tvb_increment_usage_count(tvb, 1);
}

void
tvb_set_child_real_data_tvbuff(tvbuff_t* parent, tvbuff_t* child)
{
	g_assert(parent->initialized);
	g_assert(child->initialized);
	g_assert(child->type == TVBUFF_REAL_DATA);
	add_to_used_in_list(parent, child);
}

void
tvb_set_real_data(tvbuff_t* tvb, const guint8* data, guint length, gint reported_length)
{
	g_assert(tvb->type == TVBUFF_REAL_DATA);
	g_assert(!tvb->initialized);

	if (reported_length < -1) {
		THROW(ReportedBoundsError);
	}

	tvb->real_data		= (gpointer) data;
	tvb->length		= length;
	tvb->reported_length	= reported_length;
	tvb->initialized	= TRUE;
}

tvbuff_t*
tvb_new_real_data(const guint8* data, guint length, gint reported_length, const gchar* ds_name)
{
	tvbuff_t	*tvb;

	tvb = tvb_new(TVBUFF_REAL_DATA);

	CLEANUP_PUSH(tvb_free_void, tvb);

	tvb_set_real_data(tvb, data, length, reported_length);

	/* set the data source name */
	tvb->ds_name = g_strdup( ds_name);

	CLEANUP_POP;

	return tvb;
}

/* Computes the absolute offset and length based on a possibly-negative offset
 * and a length that is possible -1 (which means "to the end of the data").
 * Returns TRUE/FALSE indicating whether the offset is in bounds or
 * not. The integer ptrs are modified with the new offset and length.
 * No exception is thrown.
 *
 * XXX - we return TRUE, not FALSE, if the offset is positive and right
 * after the end of the tvbuff (i.e., equal to the length).  We do this
 * so that a dissector constructing a subset tvbuff for the next protocol
 * will get a zero-length tvbuff, not an exception, if there's no data
 * left for the next protocol - we want the next protocol to be the one
 * that gets an exception, so the error is reported as an error in that
 * protocol rather than the containing protocol.  */
static gboolean
compute_offset_length(tvbuff_t *tvb, gint offset, gint length,
		guint *offset_ptr, guint *length_ptr, int *exception)
{
	g_assert(offset_ptr);
	g_assert(length_ptr);

	/* Compute the offset */
	if (offset >= 0) {
		/* Positive offset - relative to the beginning of the packet. */
		if ((guint) offset > tvb->reported_length) {
			if (exception) {
				*exception = ReportedBoundsError;
			}
			return FALSE;
		}
		else if ((guint) offset > tvb->length) {
			if (exception) {
				*exception = BoundsError;
			}
			return FALSE;
		}
		else {
			*offset_ptr = offset;
		}
	}
	else {
		/* Negative offset - relative to the end of the packet. */
		if ((guint) -offset > tvb->reported_length) {
			if (exception) {
				*exception = ReportedBoundsError;
			}
			return FALSE;
		}
		else if ((guint) -offset > tvb->length) {
			if (exception) {
				*exception = BoundsError;
			}
			return FALSE;
		}
		else {
			*offset_ptr = tvb->length + offset;
		}
	}

	/* Compute the length */
	if (length < -1) {
		return FALSE;
	}
	else if (length == -1) {
		*length_ptr = tvb->length - *offset_ptr;
	}
	else {
		*length_ptr = length;
	}

	return TRUE;
}


static gboolean
check_offset_length_no_exception(tvbuff_t *tvb, gint offset, gint length,
		guint *offset_ptr, guint *length_ptr, int *exception)
{
	g_assert(tvb->initialized);

	if (!compute_offset_length(tvb, offset, length, offset_ptr, length_ptr, exception)) {
		return FALSE;
	}

	if (*offset_ptr + *length_ptr <= tvb->length) {
		return TRUE;
	}
	else if (*offset_ptr + *length_ptr <= tvb->reported_length) {
		if (exception) {
			*exception = BoundsError;
		}
		return FALSE;
	}
	else {
		if (exception) {
			*exception = ReportedBoundsError;
		}
		return FALSE;
	}

	g_assert_not_reached();
}

/* Checks (+/-) offset and length and throws BoundsError if
 * either is out of bounds. Sets integer ptrs to the new offset
 * and length. */
static void
check_offset_length(tvbuff_t *tvb, gint offset, gint length,
		guint *offset_ptr, guint *length_ptr)
{
	int exception = 0;

	if (length < -1) {
		THROW(BoundsError);
	}

	if (!check_offset_length_no_exception(tvb, offset, length, offset_ptr, length_ptr, &exception)) {
		g_assert(exception > 0);
		THROW(exception);
	}
	return;
}


void
tvb_set_subset(tvbuff_t *tvb, tvbuff_t *backing,
		gint backing_offset, gint backing_length, gint reported_length)
{
	g_assert(tvb->type == TVBUFF_SUBSET);
	g_assert(!tvb->initialized);

	if (reported_length < -1) {
		THROW(ReportedBoundsError);
	}

	check_offset_length(backing, backing_offset, backing_length,
			&tvb->tvbuffs.subset.offset,
			&tvb->tvbuffs.subset.length);

	tvb->tvbuffs.subset.tvb		= backing;
	tvb->length			= tvb->tvbuffs.subset.length;

	if (reported_length == -1) {
		tvb->reported_length	= backing->reported_length - tvb->tvbuffs.subset.offset;
	}
	else {
		tvb->reported_length	= reported_length;
	}
	tvb->initialized		= TRUE;
	add_to_used_in_list(backing, tvb);

	/* Optimization. If the backing buffer has a pointer to contiguous, real data,
	 * then we can point directly to our starting offset in that buffer */
	if (backing->real_data != NULL) {
		tvb->real_data = backing->real_data + tvb->tvbuffs.subset.offset;
	}
}


tvbuff_t*
tvb_new_subset(tvbuff_t *backing, gint backing_offset, gint backing_length, gint reported_length)
{
	tvbuff_t	*tvb;

	tvb = tvb_new(TVBUFF_SUBSET);

	CLEANUP_PUSH(tvb_free_void, tvb);

	tvb_set_subset(tvb, backing, backing_offset, backing_length, reported_length);

	tvb->ds_name = backing->ds_name;
	CLEANUP_POP;

	return tvb;
}

void
tvb_composite_append(tvbuff_t* tvb, tvbuff_t* member)
{
	tvb_comp_t	*composite;

	g_assert(!tvb->initialized);
	composite = &tvb->tvbuffs.composite;
	composite->tvbs = g_slist_append( composite->tvbs, member );
	add_to_used_in_list(member, tvb);
}

void
tvb_composite_prepend(tvbuff_t* tvb, tvbuff_t* member)
{
	tvb_comp_t	*composite;

	g_assert(!tvb->initialized);
	composite = &tvb->tvbuffs.composite;
	composite->tvbs = g_slist_prepend( composite->tvbs, member );
	add_to_used_in_list(member, tvb);
}

tvbuff_t*
tvb_new_composite(void)
{
	return tvb_new(TVBUFF_COMPOSITE);
}

void
tvb_composite_finalize(tvbuff_t* tvb)
{
	GSList		*slist;
	guint		num_members;
	tvbuff_t	*member_tvb;
	tvb_comp_t	*composite;
	int		i = 0;

	g_assert(!tvb->initialized);
	g_assert(tvb->length == 0);

	composite = &tvb->tvbuffs.composite;
	num_members = g_slist_length(composite->tvbs);

	composite->start_offsets = g_new(guint, num_members);
	composite->end_offsets = g_new(guint, num_members);

	for (slist = composite->tvbs; slist != NULL; slist = slist->next) {
		g_assert((guint) i < num_members);
		member_tvb = slist->data;
		composite->start_offsets[i] = tvb->length;
		tvb->length += member_tvb->length;
		composite->end_offsets[i] = tvb->length - 1;
		i++;
	}

	tvb->initialized = TRUE;
}



guint
tvb_length(tvbuff_t* tvb)
{
	g_assert(tvb->initialized);

	return tvb->length;
}

gint
tvb_length_remaining(tvbuff_t *tvb, gint offset)
{
	guint	abs_offset, abs_length;

	g_assert(tvb->initialized);

	if (compute_offset_length(tvb, offset, -1, &abs_offset, &abs_length, NULL)) {
		return abs_length;
	}
	else {
		return -1;
	}
}

gint
tvb_ensure_length_remaining(tvbuff_t *tvb, gint offset)
{
	gint retval;

	retval = tvb_length_remaining(tvb, offset);

	if (retval == -1) {
		THROW(ReportedBoundsError);
		return -1;	/* squelch compiler complaint */
	}
	else {
		return retval;
	}
}




/* Validates that 'length' bytes are available starting from
 * offset (pos/neg). Does not throw BoundsError exception. */
gboolean
tvb_bytes_exist(tvbuff_t *tvb, gint offset, gint length)
{
	guint		abs_offset, abs_length;

	g_assert(tvb->initialized);

	if (!compute_offset_length(tvb, offset, length, &abs_offset, &abs_length, NULL))
		return FALSE;

	if (abs_offset + abs_length <= tvb->length) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}

gboolean
tvb_offset_exists(tvbuff_t *tvb, gint offset)
{
	guint		abs_offset, abs_length;

	g_assert(tvb->initialized);
	if (!compute_offset_length(tvb, offset, -1, &abs_offset, &abs_length, NULL))
		return FALSE;

	if (abs_offset < tvb->length) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}

guint
tvb_reported_length(tvbuff_t* tvb)
{
	g_assert(tvb->initialized);

	return tvb->reported_length;
}

gint
tvb_reported_length_remaining(tvbuff_t *tvb, gint offset)
{
	guint	abs_offset, abs_length;

	g_assert(tvb->initialized);

	if (compute_offset_length(tvb, offset, -1, &abs_offset, &abs_length, NULL)) {
		if (tvb->reported_length >= abs_offset)
			return tvb->reported_length - abs_offset;
		else
			return -1;
	}
	else {
		return -1;
	}
}

/* Set the reported length of a tvbuff to a given value; used for protocols
   whose headers contain an explicit length and where the calling
   dissector's payload may include padding as well as the packet for
   this protocol.

   Also adjusts the data length. */
void
tvb_set_reported_length(tvbuff_t* tvb, guint reported_length)
{
	g_assert(tvb->initialized);

	if (reported_length > tvb->reported_length)
		THROW(ReportedBoundsError);

	tvb->reported_length = reported_length;
	if (reported_length < tvb->length)
		tvb->length = reported_length;
}


static guint8*
first_real_data_ptr(tvbuff_t *tvb)
{
	tvbuff_t	*member;

	switch(tvb->type) {
		case TVBUFF_REAL_DATA:
			return tvb->real_data;
		case TVBUFF_SUBSET:
			member = tvb->tvbuffs.subset.tvb;
			return first_real_data_ptr(member);
		case TVBUFF_COMPOSITE:
			member = tvb->tvbuffs.composite.tvbs->data;
			return first_real_data_ptr(member);
	}

	g_assert_not_reached();
	return NULL;
}

static int
offset_from_real_beginning(tvbuff_t *tvb, int counter)
{
	tvbuff_t	*member;

	switch(tvb->type) {
		case TVBUFF_REAL_DATA:
			return counter;
		case TVBUFF_SUBSET:
			member = tvb->tvbuffs.subset.tvb;
			return offset_from_real_beginning(member, counter + tvb->tvbuffs.subset.offset);
		case TVBUFF_COMPOSITE:
			member = tvb->tvbuffs.composite.tvbs->data;
			return offset_from_real_beginning(member, counter);
	}

	g_assert_not_reached();
	return 0;
}

gint
tvb_raw_offset(tvbuff_t *tvb)
{
	if (tvb->raw_offset == -1) {
		tvb->raw_offset = offset_from_real_beginning(tvb, 0);
	}
	return tvb->raw_offset;
}

static guint8*
composite_ensure_contiguous(tvbuff_t *tvb, guint abs_offset, guint abs_length)
{
	guint		i, num_members;
	tvb_comp_t	*composite;
	tvbuff_t	*member_tvb = NULL;
	guint		member_offset, member_length;
	GSList		*slist;

	g_assert(tvb->type == TVBUFF_COMPOSITE);

	/* Maybe the range specified by offset/length
	 * is contiguous inside one of the member tvbuffs */
	composite = &tvb->tvbuffs.composite;
	num_members = g_slist_length(composite->tvbs);

	for (i = 0; i < num_members; i++) {
		if (abs_offset <= composite->end_offsets[i]) {
			slist = g_slist_nth(composite->tvbs, i);
			member_tvb = slist->data;
			break;
		}
	}
	g_assert(member_tvb);

	if (check_offset_length_no_exception(member_tvb, abs_offset - composite->start_offsets[i],
				abs_length, &member_offset, &member_length, NULL)) {

		g_assert(!tvb->real_data);
		return ensure_contiguous(member_tvb, member_offset, member_length);
	}
	else {
		tvb->real_data = tvb_memdup(tvb, 0, -1);
		return tvb->real_data + abs_offset;
	}

	g_assert_not_reached();
	return NULL;
}

static guint8*
ensure_contiguous(tvbuff_t *tvb, gint offset, gint length)
{
	guint	abs_offset, abs_length;

	check_offset_length(tvb, offset, length, &abs_offset, &abs_length);

	if (tvb->real_data) {
		return tvb->real_data + abs_offset;
	}
	else {
		switch(tvb->type) {
			case TVBUFF_REAL_DATA:
				g_assert_not_reached();
			case TVBUFF_SUBSET:
				return ensure_contiguous(tvb->tvbuffs.subset.tvb,
						abs_offset - tvb->tvbuffs.subset.offset,
						abs_length);
			case TVBUFF_COMPOSITE:
				return composite_ensure_contiguous(tvb, abs_offset, abs_length);
		}
	}

	g_assert_not_reached();
	return NULL;
}

static const guint8*
guint8_find(const guint8* haystack, size_t haystacklen, guint8 needle)
{
	const guint8	*b;
	int		i;

	for (b = haystack, i = 0; (guint) i < haystacklen; i++, b++) {
		if (*b == needle) {
			return b;
		}
	}

	return NULL;
}

static const guint8*
guint8_pbrk(const guint8* haystack, size_t haystacklen, guint8 *needles)
{
	const guint8	*b;
	int		i;
	guint8		item, *needlep, needle;

	for (b = haystack, i = 0; (guint) i < haystacklen; i++, b++) {
		item = *b;
		needlep = needles;
		while ((needle = *needlep) != '\0') {
			if (item == needle)
				return b;
			needlep++;
		}
	}

	return NULL;
}



/************** ACCESSORS **************/

static guint8*
composite_memcpy(tvbuff_t *tvb, guint8* target, guint abs_offset, guint abs_length)
{
	guint		i, num_members;
	tvb_comp_t	*composite;
	tvbuff_t	*member_tvb = NULL;
	guint		member_offset, member_length;
	gboolean	retval;
	GSList		*slist;

	g_assert(tvb->type == TVBUFF_COMPOSITE);

	/* Maybe the range specified by offset/length
	 * is contiguous inside one of the member tvbuffs */
	composite = &tvb->tvbuffs.composite;
	num_members = g_slist_length(composite->tvbs);

	for (i = 0; i < num_members; i++) {
		if (abs_offset <= composite->end_offsets[i]) {
			slist = g_slist_nth(composite->tvbs, i);
			member_tvb = slist->data;
			break;
		}
	}
	g_assert(member_tvb);

	if (check_offset_length_no_exception(member_tvb, abs_offset - composite->start_offsets[i],
				abs_length, &member_offset, &member_length, NULL)) {

		g_assert(!tvb->real_data);
		return tvb_memcpy(member_tvb, target, member_offset, member_length);
	}
	else {
		/* The requested data is non-contiguous inside
		 * the member tvb. We have to memcpy() the part that's in the member tvb,
		 * then iterate across the other member tvb's, copying their portions
		 * until we have copied all data.
		 */
		retval = compute_offset_length(member_tvb, abs_offset - composite->start_offsets[i], -1,
				&member_offset, &member_length, NULL);
		g_assert(retval);

		tvb_memcpy(member_tvb, target, member_offset, member_length);
		abs_offset	+= member_length;
		abs_length	-= member_length;

		/* Recurse */
		if (abs_length > 0) {
			composite_memcpy(tvb, target + member_length, abs_offset, abs_length);
		}

		return target;
	}

	g_assert_not_reached();
	return NULL;
}

guint8*
tvb_memcpy(tvbuff_t *tvb, guint8* target, gint offset, gint length)
{
	guint	abs_offset, abs_length;

	g_assert(length >= -1);
	check_offset_length(tvb, offset, length, &abs_offset, &abs_length);

	if (tvb->real_data) {
		return (guint8*) memcpy(target, tvb->real_data + abs_offset, abs_length);
	}

	switch(tvb->type) {
		case TVBUFF_REAL_DATA:
			g_assert_not_reached();

		case TVBUFF_SUBSET:
			return tvb_memcpy(tvb->tvbuffs.subset.tvb, target,
					abs_offset - tvb->tvbuffs.subset.offset,
					abs_length);

		case TVBUFF_COMPOSITE:
			return composite_memcpy(tvb, target, offset, length);
	}

	g_assert_not_reached();
	return NULL;
}


guint8*
tvb_memdup(tvbuff_t *tvb, gint offset, gint length)
{
	guint	abs_offset, abs_length;
	guint8	*duped;

	check_offset_length(tvb, offset, length, &abs_offset, &abs_length);

	duped = g_malloc(abs_length);
	return tvb_memcpy(tvb, duped, abs_offset, abs_length);
}


	
const guint8*
tvb_get_ptr(tvbuff_t *tvb, gint offset, gint length)
{
	return ensure_contiguous(tvb, offset, length);
}

guint8
tvb_get_guint8(tvbuff_t *tvb, gint offset)
{
	guint8* ptr;

	ptr = ensure_contiguous(tvb, offset, sizeof(guint8));
	return *ptr;
}

guint16
tvb_get_ntohs(tvbuff_t *tvb, gint offset)
{
	guint8* ptr;

	ptr = ensure_contiguous(tvb, offset, sizeof(guint16));
	return pntohs(ptr);
}

guint32
tvb_get_ntoh24(tvbuff_t *tvb, gint offset)
{
	guint8* ptr;

	ptr = ensure_contiguous(tvb, offset, 3);
	return pntoh24(ptr);
}

guint32
tvb_get_ntohl(tvbuff_t *tvb, gint offset)
{
	guint8* ptr;

	ptr = ensure_contiguous(tvb, offset, sizeof(guint32));
	return pntohl(ptr);
}

guint16
tvb_get_letohs(tvbuff_t *tvb, gint offset)
{
	guint8* ptr;

	ptr = ensure_contiguous(tvb, offset, sizeof(guint16));
	return pletohs(ptr);
}

guint32
tvb_get_letoh24(tvbuff_t *tvb, gint offset)
{
	guint8* ptr;

	ptr = ensure_contiguous(tvb, offset, 3);
	return pletoh24(ptr);
}

guint32
tvb_get_letohl(tvbuff_t *tvb, gint offset)
{
	guint8* ptr;

	ptr = ensure_contiguous(tvb, offset, sizeof(guint32));
	return pletohl(ptr);
}

/* Find first occurence of needle in tvbuff, starting at offset. Searches
 * at most maxlength number of bytes; if maxlength is -1, searches to
 * end of tvbuff.
 * Returns the offset of the found needle, or -1 if not found.
 * Will not throw an exception, even if maxlength exceeds boundary of tvbuff;
 * in that case, -1 will be returned if the boundary is reached before
 * finding needle. */
gint
tvb_find_guint8(tvbuff_t *tvb, gint offset, gint maxlength, guint8 needle)
{
	const guint8	*result;
	guint		abs_offset, junk_length;
	guint		tvbufflen;
	guint		limit;

	check_offset_length(tvb, offset, 0, &abs_offset, &junk_length);

	/* Only search to end of tvbuff, w/o throwing exception. */
	tvbufflen = tvb_length_remaining(tvb, abs_offset);
	if (maxlength == -1) {
		/* No maximum length specified; search to end of tvbuff. */
		limit = tvbufflen;
	}
	else if (tvbufflen < (guint) maxlength) {
		/* Maximum length goes past end of tvbuff; search to end
		   of tvbuff. */
		limit = tvbufflen;
	}
	else {
		/* Maximum length doesn't go past end of tvbuff; search
		   to that value. */
		limit = maxlength;
	}

	/* If we have real data, perform our search now. */
	if (tvb->real_data) {
		result = guint8_find(tvb->real_data + abs_offset, limit, needle);
		if (result == NULL) {
			return -1;
		}
		else {
			return result - tvb->real_data;
		}
	}

	switch(tvb->type) {
		case TVBUFF_REAL_DATA:
			g_assert_not_reached();

		case TVBUFF_SUBSET:
			return tvb_find_guint8(tvb->tvbuffs.subset.tvb,
					abs_offset - tvb->tvbuffs.subset.offset,
					limit, needle);

		case TVBUFF_COMPOSITE:
			g_assert_not_reached();
			/* XXX - return composite_find_guint8(tvb, offset, limit, needle); */
	}

	g_assert_not_reached();
	return -1;
}

/* Find first occurence of any of the needles in tvbuff, starting at offset.
 * Searches at most maxlength number of bytes; if maxlength is -1, searches
 * to end of tvbuff.
 * Returns the offset of the found needle, or -1 if not found.
 * Will not throw an exception, even if maxlength exceeds boundary of tvbuff;
 * in that case, -1 will be returned if the boundary is reached before
 * finding needle. */
gint
tvb_pbrk_guint8(tvbuff_t *tvb, gint offset, gint maxlength, guint8 *needles)
{
	const guint8	*result;
	guint		abs_offset, junk_length;
	guint		tvbufflen;
	guint		limit;

	check_offset_length(tvb, offset, 0, &abs_offset, &junk_length);

	/* Only search to end of tvbuff, w/o throwing exception. */
	tvbufflen = tvb_length_remaining(tvb, abs_offset);
	if (maxlength == -1) {
		/* No maximum length specified; search to end of tvbuff. */
		limit = tvbufflen;
	}
	else if (tvbufflen < (guint) maxlength) {
		/* Maximum length goes past end of tvbuff; search to end
		   of tvbuff. */
		limit = tvbufflen;
	}
	else {
		/* Maximum length doesn't go past end of tvbuff; search
		   to that value. */
		limit = maxlength;
	}

	/* If we have real data, perform our search now. */
	if (tvb->real_data) {
		result = guint8_pbrk(tvb->real_data + abs_offset, limit, needles);
		if (result == NULL) {
			return -1;
		}
		else {
			return result - tvb->real_data;
		}
	}

	switch(tvb->type) {
		case TVBUFF_REAL_DATA:
			g_assert_not_reached();

		case TVBUFF_SUBSET:
			return tvb_pbrk_guint8(tvb->tvbuffs.subset.tvb,
					abs_offset - tvb->tvbuffs.subset.offset,
					limit, needles);

		case TVBUFF_COMPOSITE:
			g_assert_not_reached();
			/* XXX - return composite_pbrk_guint8(tvb, offset, limit, needle); */
	}

	g_assert_not_reached();
	return -1;
}

/* Find size of stringz (NUL-terminated string) by looking for terminating
 * NUL.  The size of the string includes the terminating NUL.
 *
 * If the NUL isn't found, it throws the appropriate exception.
 */
guint
tvb_strsize(tvbuff_t *tvb, gint offset)
{
	guint	abs_offset, junk_length;
	gint	nul_offset;

	check_offset_length(tvb, offset, 0, &abs_offset, &junk_length);
	nul_offset = tvb_find_guint8(tvb, abs_offset, -1, 0);
	if (nul_offset == -1) {
		/*
		 * OK, we hit the end of the tvbuff, so we should throw
		 * an exception.
		 *
		 * Did we hit the end of the captured data, or the end
		 * of the actual data?  If there's less captured data
		 * than actual data, we presumably hit the end of the
		 * captured data, otherwise we hit the end of the actual
		 * data.
		 */
		if (tvb_length(tvb) < tvb_reported_length(tvb)) {
			THROW(BoundsError);
		} else {
			THROW(ReportedBoundsError);
		}
	}
	return (nul_offset - abs_offset) + 1;
}

/* Find length of string by looking for end of string ('\0'), up to
 * 'maxlength' characters'; if 'maxlength' is -1, searches to end
 * of tvbuff.
 * Returns -1 if 'maxlength' reached before finding EOS. */
gint
tvb_strnlen(tvbuff_t *tvb, gint offset, guint maxlength)
{
	gint	result_offset;
	guint	abs_offset, junk_length;

	check_offset_length(tvb, offset, 0, &abs_offset, &junk_length);

	result_offset = tvb_find_guint8(tvb, abs_offset, maxlength, 0);

	if (result_offset == -1) {
		return -1;
	}
	else {
		return result_offset - abs_offset;
	}
}

/*
 * Implement strneql etc
 */

/*
 * Call strncmp after checking if enough chars left, returning 0 if
 * it returns 0 (meaning "equal") and -1 otherwise, otherwise return -1.
 */
gint
tvb_strneql(tvbuff_t *tvb, gint offset, const guint8 *str, gint size)
{
	guint8 *ptr;

	ptr = ensure_contiguous(tvb, offset, size);

	if (ptr) {
		int cmp = strncmp(ptr, str, size);

		/*
		 * Return 0 if equal, -1 otherwise.
		 */
		return (cmp == 0 ? 0 : -1);
	} else {
		/*
		 * Not enough characters in the tvbuff to match the
		 * string.
		 */
		return -1;
	}
}

/*
 * Call strncasecmp after checking if enough chars left, returning 0 if
 * it returns 0 (meaning "equal") and -1 otherwise, otherwise return -1.
 */
gint
tvb_strncaseeql(tvbuff_t *tvb, gint offset, const guint8 *str, gint size)
{
	guint8 *ptr;

	ptr = ensure_contiguous(tvb, offset, size);

	if (ptr) {
		int cmp = strncasecmp(ptr, str, size);

		/*
		 * Return 0 if equal, -1 otherwise.
		 */
		return (cmp == 0 ? 0 : -1);
	} else {
		/*
		 * Not enough characters in the tvbuff to match the
		 * string.
		 */
		return -1;
	}
}

/*
 * Call memcmp after checking if enough chars left, returning 0 if
 * it returns 0 (meaning "equal") and -1 otherwise, otherwise return -1.
 */
gint
tvb_memeql(tvbuff_t *tvb, gint offset, const guint8 *str, gint size)
{
	guint8 *ptr;

	ptr = ensure_contiguous(tvb, offset, size);

	if (ptr) {
		int cmp = memcmp(ptr, str, size);

		/*
		 * Return 0 if equal, -1 otherwise.
		 */
		return (cmp == 0 ? 0 : -1);
	} else {
		/*
		 * Not enough characters in the tvbuff to match the
		 * string.
		 */
		return -1;
	}
}

/*
 * Format the data in the tvb from offset for length ...
 */

guint8 *
tvb_format_text(tvbuff_t *tvb, gint offset, gint size)
{
  guint8 *ptr;
  gint len = size;

  if ((ptr = ensure_contiguous(tvb, offset, size)) == NULL) {

    len = tvb_length_remaining(tvb, offset);
    ptr = ensure_contiguous(tvb, offset, len);

  }

  return format_text(ptr, len);
 
}

/* Looks for a stringz (NUL-terminated string) in tvbuff and copies
 * no more than maxlength number of bytes, including terminating NUL, to buffer.
 * Returns length of string (not including terminating NUL), or -1 if the string was
 * truncated in the buffer due to not having reached the terminating NUL.
 * In this way, it acts like snprintf().
 *
 * When processing a packet where the remaining number of bytes is less
 * than maxlength, an exception is not thrown if the end of the packet
 * is reached before the NUL is found. If no NUL is found before reaching
 * the end of the short packet, -1 is still returned, and the string
 * is truncated with a NUL, albeit not at buffer[maxlength], but
 * at the correct spot, terminating the string.
 *
 * *bytes_copied will contain the number of bytes actually copied,
 * including the terminating-NUL.
 */
gint
_tvb_get_nstringz(tvbuff_t *tvb, gint offset, guint maxlength, guint8* buffer,
		gint *bytes_copied)
{
	gint	stringlen;
	guint	abs_offset, junk_length;
	gint	limit, len;
	gboolean decreased_max = FALSE;

	check_offset_length(tvb, offset, 0, &abs_offset, &junk_length);

	if (maxlength == 0) {
		buffer[0] = 0;
		return 0;
	}

	/* Only read to end of tvbuff, w/o throwing exception. */
	len = tvb_length_remaining(tvb, abs_offset);

	/* check_offset_length() won't throw an exception if we're
	 * looking at the byte immediately after the end of the tvbuff. */
	if (len == 0) {
		THROW(ReportedBoundsError);
	}

	/* This should not happen because check_offset_length() would
	* have already thrown an exception if 'offset' were out-of-bounds.
	*/
	g_assert(len != -1);

	if ((guint)len < maxlength) {
		limit = len;
		decreased_max = TRUE;
	}
	else {
		limit = maxlength;
	}

	stringlen = tvb_strnlen(tvb, abs_offset, limit);
	/* If NUL wasn't found, copy the data and return -1 */
	if (stringlen == -1) {
		tvb_memcpy(tvb, buffer, abs_offset, limit);
		if (decreased_max) {
			buffer[limit] = 0;
			/* Add 1 for the extra NUL that we set at buffer[limit],
			 * pretending that it was copied as part of the string. */
			*bytes_copied = limit + 1;
		}
		else {
			*bytes_copied = limit;
		}
		return -1;
	}

	/* Copy the string to buffer */
	tvb_memcpy(tvb, buffer, abs_offset, stringlen + 1);
	*bytes_copied = stringlen + 1;
	return stringlen;
}

/* Looks for a stringz (NUL-terminated string) in tvbuff and copies
 * no more than maxlength number of bytes, including terminating NUL, to buffer.
 * Returns length of string (not including terminating NUL), or -1 if the string was
 * truncated in the buffer due to not having reached the terminating NUL.
 * In this way, it acts like snprintf().
 *
 * When processing a packet where the remaining number of bytes is less
 * than maxlength, an exception is not thrown if the end of the packet
 * is reached before the NUL is found. If no NUL is found before reaching
 * the end of the short packet, -1 is still returned, and the string
 * is truncated with a NUL, albeit not at buffer[maxlength], but
 * at the correct spot, terminating the string.
 */
gint
tvb_get_nstringz(tvbuff_t *tvb, gint offset, guint maxlength, guint8* buffer)
{
	gint bytes_copied;

	return _tvb_get_nstringz(tvb, offset, maxlength, buffer, &bytes_copied);
}

/* Like tvb_get_nstringz(), but never returns -1. The string is guaranteed to
 * have a terminating NUL. If the string was truncated when copied into buffer,
 * a NUL is placed at the end of buffer to terminate it.
 */
gint
tvb_get_nstringz0(tvbuff_t *tvb, gint offset, guint maxlength, guint8* buffer)
{
	gint	len, bytes_copied;

	len = _tvb_get_nstringz(tvb, offset, maxlength, buffer, &bytes_copied);

	if (len == -1) {
		buffer[maxlength] = 0;
		return bytes_copied - 1;
	}
	else {
		return len;
	}
}

/*
 * Given a tvbuff, an offset into the tvbuff, and a length that starts
 * at that offset (which may be -1 for "all the way to the end of the
 * tvbuff"), find the end of the (putative) line that starts at the
 * specified offset in the tvbuff, going no further than the specified
 * length.
 *
 * Return the length of the line (not counting the line terminator at
 * the end), or the amount of data remaining in the buffer if we don't
 * find a line terminator.
 *
 * Set "*next_offset" to the offset of the character past the line
 * terminator, or past the end of the buffer if we don't find a line
 * terminator.
 */
gint
tvb_find_line_end(tvbuff_t *tvb, gint offset, int len, gint *next_offset)
{
	gint eob_offset;
	gint eol_offset;
	int linelen;

	if (len == -1)
		len = tvb_length_remaining(tvb, offset);
	/*
	 * XXX - what if "len" is still -1, meaning "offset is past the
	 * end of the tvbuff"?
	 */
	eob_offset = offset + len;

	/*
	 * Look either for a CR or an LF.
	 */
	eol_offset = tvb_pbrk_guint8(tvb, offset, len, "\r\n");
	if (eol_offset == -1) {
		/*
		 * No CR or LF - line is presumably continued in next packet.
		 * We pretend the line runs to the end of the tvbuff.
		 */
		linelen = eob_offset - offset;
		*next_offset = eob_offset;
	} else {
		/*
		 * Find the number of bytes between the starting offset
		 * and the CR or LF.
		 */
		linelen = eol_offset - offset;

		/*
		 * Is it a CR?
		 */
		if (tvb_get_guint8(tvb, eol_offset) == '\r') {
			/*
			 * Yes - is it followed by an LF?
			 */
			if (eol_offset + 1 < eob_offset &&
			    tvb_get_guint8(tvb, eol_offset + 1) == '\n') {
				/*
				 * Yes; skip over the CR.
				 */
				eol_offset++;
			}
		}

		/*
		 * Return the offset of the character after the last
		 * character in the line, skipping over the last character
		 * in the line terminator.
		 */
		*next_offset = eol_offset + 1;
	}
	return linelen;
}

/*
 * Given a tvbuff, an offset into the tvbuff, and a length that starts
 * at that offset (which may be -1 for "all the way to the end of the
 * tvbuff"), find the end of the (putative) line that starts at the
 * specified offset in the tvbuff, going no further than the specified
 * length.
 *
 * However, treat quoted strings inside the buffer specially - don't
 * treat newlines in quoted strings as line terminators.
 *
 * Return the length of the line (not counting the line terminator at
 * the end), or the amount of data remaining in the buffer if we don't
 * find a line terminator.
 *
 * Set "*next_offset" to the offset of the character past the line
 * terminator, or past the end of the buffer if we don't find a line
 * terminator.
 */
gint
tvb_find_line_end_unquoted(tvbuff_t *tvb, gint offset, int len,
    gint *next_offset)
{
	gint cur_offset, char_offset;
	gboolean is_quoted;
	u_char c;
	gint eob_offset;
	int linelen;

	if (len == -1)
		len = tvb_length_remaining(tvb, offset);
	/*
	 * XXX - what if "len" is still -1, meaning "offset is past the
	 * end of the tvbuff"?
	 */
	eob_offset = offset + len;

	cur_offset = offset;
	is_quoted = FALSE;
	for (;;) {
	    	/*
		 * Is this part of the string quoted?
		 */
		if (is_quoted) {
			/*
			 * Yes - look only for the terminating quote.
			 */
			char_offset = tvb_find_guint8(tvb, cur_offset, len,
			    '"');
		} else {
			/*
			 * Look either for a CR, an LF, or a '"'.
			 */
			char_offset = tvb_pbrk_guint8(tvb, cur_offset, len,
			    "\r\n\"");
		}
		if (char_offset == -1) {
			/*
			 * Not found - line is presumably continued in
			 * next packet.
			 * We pretend the line runs to the end of the tvbuff.
			 */
			linelen = eob_offset - offset;
			*next_offset = eob_offset;
			break;
		}
			
		if (is_quoted) {
			/*
			 * We're processing a quoted string.
			 * We only looked for ", so we know it's a ";
			 * as we're processing a quoted string, it's a
			 * closing quote.
			 */
			is_quoted = FALSE;
		} else {
			/*
			 * OK, what is it?
			 */
			c = tvb_get_guint8(tvb, char_offset);
			if (c == '"') {
				/*
				 * Un-quoted "; it begins a quoted
				 * string.
				 */
				is_quoted = TRUE;
			} else {
				/*
				 * It's a CR or LF; we've found a line
				 * terminator.
				 *
				 * Find the number of bytes between the
				 * starting offset and the CR or LF.
				 */
				linelen = char_offset - offset;

				/*
				 * Is it a CR?
				 */
				if (c == '\r') {
					/*
					 * Yes; is it followed by an LF?
					 */
					if (char_offset + 1 < eob_offset &&
					    tvb_get_guint8(tvb, char_offset + 1)
					      == '\n') {
						/*
						 * Yes; skip over the CR.
						 */
						char_offset++;
					}
				}

				/*
				 * Return the offset of the character after
				 * the last character in the line, skipping
				 * over the last character in the line
				 * terminator, and quit.
				 */
				*next_offset = char_offset + 1;
				break;
			}
		}

		/*
		 * Step past the character we found.
		 */
		cur_offset = char_offset + 1;
		if (cur_offset >= eob_offset) {
			/*
			 * The character we found was the last character
			 * in the tvbuff - line is presumably continued in
			 * next packet.
			 * We pretend the line runs to the end of the tvbuff.
			 */
			linelen = eob_offset - offset;
			*next_offset = eob_offset;
			break;
		}
	}
	return linelen;
}

/*
 * Format a bunch of data from a tvbuff as bytes, returning a pointer
 * to the string with the formatted data.
 */
gchar *
tvb_bytes_to_str(tvbuff_t *tvb, gint offset, gint len)
{
	return bytes_to_str(tvb_get_ptr(tvb, offset, len), len);
}

gchar*
tvb_get_name(tvbuff_t* tvb)
{
	return tvb->ds_name;
}
