/* drange.c
 * Routines for providing general range support to the dfilter library
 *
 * $Id: drange.c,v 1.2 2001/03/02 17:04:23 gram Exp $
 * 
 * Copyright (c) 2000 by Ed Warnicke <hagbard@physics.rutgers.edu>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs
 * Copyright 1999 Gerald Combs
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

#include "drange.h"

/* drange_node constructor */
drange_node*
drange_node_new(void)
{
  drange_node* new_range_node;

  new_range_node = g_malloc(sizeof(drange_node));
  new_range_node->start_offset = 0;
  new_range_node->length = 0;
  new_range_node->end_offset = 0;
  new_range_node->ending = UNINITIALIZED;
  return new_range_node;
}

/* drange_node destructor */
void
drange_node_free(drange_node* drnode)
{
  g_free(drnode);
}

/* drange_node accessors */  
gint
drange_node_get_start_offset(drange_node* drnode)
{
  g_assert(drnode->ending != UNINITIALIZED);
  return drnode->start_offset;
}

gint
drange_node_get_length(drange_node* drnode)
{
  g_assert(drnode->ending == LENGTH);
  return drnode->length;
}

gint
drange_node_get_end_offset(drange_node* drnode)
{
  g_assert(drnode->ending == OFFSET);
  return drnode->end_offset;
}

drange_node_end_t
drange_node_get_ending(drange_node* drnode)
{
  g_assert(drnode->ending != UNINITIALIZED);
  return drnode->ending;
}

/* drange_node mutators */
void
drange_node_set_start_offset(drange_node* drnode, gint offset)
{
  drnode->start_offset = offset;
}

void
drange_node_set_length(drange_node* drnode, gint length)
{
  drnode->length = length;
  drnode->ending = LENGTH;
}

void
drange_node_set_end_offset(drange_node* drnode, gint offset)
{
  drnode->end_offset = offset;
  drnode->ending = OFFSET;
}


void
drange_node_set_to_the_end(drange_node* drnode)
{
  drnode->ending = TO_THE_END;
}

/* drange constructor */
drange*
drange_new(void)
{
  drange* new_drange;
  new_drange = g_malloc(sizeof(drange));
  new_drange->range_list = NULL;
  new_drange->has_total_length = TRUE;
  new_drange->total_length = 0;
  new_drange->min_start_offset = G_MAXINT;
  new_drange->max_start_offset = G_MININT;
  return new_drange;
}

static void
drange_append_wrapper(gpointer data, gpointer user_data)
{
	drange_node *drnode = data;
	drange		*dr = user_data;

	drange_append_drange_node(dr, drnode);
}

drange*
drange_new_from_list(GSList *list)
{
	drange	*new_drange;

	new_drange = drange_new();
	g_slist_foreach(list, drange_append_wrapper, new_drange);
	return new_drange;
}

  
static void
drange_node_free_wrapper(gpointer data, gpointer userdata)
{
  g_free(data);
}

/* drange destructor */
void
drange_free(drange* dr)
{
  drange_node_free_list(dr->range_list);
  g_free(dr);
}

/* Call drange_node destructor on all list items */
void
drange_node_free_list(GSList* list)
{
  g_slist_foreach(list, drange_node_free_wrapper, NULL);
}

/* drange accessors */
gboolean drange_has_total_length(drange* dr){ return dr->has_total_length; }
gint drange_get_total_length(drange* dr) { return dr->total_length; }
gint drange_get_min_start_offset(drange* dr) { return dr->min_start_offset; }
gint drange_get_max_start_offset(drange* dr) { return dr->max_start_offset; }
    
static void
update_drange_with_node(drange *dr, drange_node *drnode)
{
    if(drnode->ending == TO_THE_END){
      dr->has_total_length = FALSE;
    }
    else if(dr->has_total_length){
      dr->total_length += drnode->length;
    }
    if(drnode->start_offset < dr->min_start_offset){
      dr->min_start_offset = drnode->start_offset;
    }
    if(drnode->start_offset > dr->max_start_offset){
      dr->max_start_offset = drnode->start_offset;
    }
}

/* drange mutators */
void
drange_prepend_drange_node(drange* dr, drange_node* drnode)
{
  if(drnode != NULL){
    dr->range_list = g_slist_prepend(dr->range_list,drnode);
    update_drange_with_node(dr, drnode);
  }  
}

void
drange_append_drange_node(drange* dr, drange_node* drnode)
{
  if(drnode != NULL){
    dr->range_list = g_slist_append(dr->range_list,drnode);
    update_drange_with_node(dr, drnode);
  }  
}

void
drange_foreach_drange_node(drange* dr, GFunc func, gpointer funcdata)
{
  g_slist_foreach(dr->range_list,func,funcdata);
}
