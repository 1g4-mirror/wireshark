/* buffer.c
 *
 * $Id: buffer.c,v 1.12 2001/11/13 23:55:43 gram Exp $
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
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
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include "buffer.h"

/* Initializes a buffer with a certain amount of allocated space */
void buffer_init(Buffer* buffer, unsigned int space)
{
	buffer->data = (u_char*)g_malloc(space);
	buffer->allocated = space;
	buffer->start = 0;
	buffer->first_free = 0;
}

/* Frees the memory used by a buffer, and the buffer struct */
void buffer_free(Buffer* buffer)
{
	g_free(buffer->data);
}

/* Assures that there are 'space' bytes at the end of the used space
	so that another routine can copy directly into the buffer space. After
	doing that, the routine will also want to run
	buffer_increase_length(). */
void buffer_assure_space(Buffer* buffer, unsigned int space)
{
	unsigned int available_at_end = buffer->allocated - buffer->first_free;
	unsigned int space_used;
	int space_at_beginning;

	/* If we've got the space already, good! */
	if (space <= available_at_end) {
		return;
	}

	/* Maybe we don't have the space available at the end, but we would
		if we moved the used space back to the beginning of the
		allocation. The buffer could have become fragmented through lots
		of calls to buffer_remove_start(). I'm using buffer->start as the
		same as 'available_at_start' in this comparison. */

	/* or maybe there's just no more room. */

	space_at_beginning = buffer->start >= space;
	if (space_at_beginning || buffer->start > 0) {
		space_used = buffer->first_free - buffer->start;
		/* this memory copy better be safe for overlapping memory regions! */
		memmove(buffer->data, buffer->data + buffer->start, space_used);
		buffer->start = 0;
		buffer->first_free = space_used;
	}
	/*if (buffer->start >= space) {*/
	if (space_at_beginning) {
		return;
	}

	/* We'll allocate more space */
	buffer->allocated += space + 1024;
	buffer->data = (u_char*)g_realloc(buffer->data, buffer->allocated);
}

void buffer_append(Buffer* buffer, u_char *from, unsigned int bytes)
{
	buffer_assure_space(buffer, bytes);
	memcpy(buffer->data + buffer->first_free, from, bytes);
	buffer->first_free += bytes;
}

void buffer_remove_start(Buffer* buffer, unsigned int bytes)
{
	if (buffer->start + bytes > buffer->first_free) {
		g_error("buffer_remove_start trying to remove %d bytes. s=%d ff=%d!\n",
			bytes, buffer->start, buffer->first_free);
		exit(1);
	}
	buffer->start += bytes;

	if (buffer->start == buffer->first_free) {
		buffer->start = 0;
		buffer->first_free = 0;
	}
}


#ifndef SOME_FUNCTIONS_ARE_DEFINES
void buffer_increase_length(Buffer* buffer, unsigned int bytes)
{
	buffer->first_free += bytes;
}
#endif

#ifndef SOME_FUNCTIONS_ARE_DEFINES
unsigned int buffer_length(Buffer* buffer)
{
	return buffer->first_free - buffer->start;
}
#endif

#ifndef SOME_FUNCTIONS_ARE_DEFINES
u_char* buffer_start_ptr(Buffer* buffer)
{
	return buffer->data + buffer->start;
}
#endif

#ifndef SOME_FUNCTIONS_ARE_DEFINES
u_char* buffer_end_ptr(Buffer* buffer)
{
	return buffer->data + buffer->first_free;
}
#endif
