/*
 * $Id: syntax-tree.c,v 1.4 2001/10/26 17:29:11 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 2001 Gerald Combs
 *
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

#include "syntax-tree.h"

/* Keep track of sttype_t's via their sttype_id_t number */
static sttype_t* type_list[STTYPE_NUM_TYPES];

/* These are the sttype_t registration function prototypes. */
void sttype_register_integer(void);
void sttype_register_pointer(void);
void sttype_register_range(void);
void sttype_register_string(void);
void sttype_register_test(void);


#define STNODE_MAGIC	0xe9b00b9e


void
sttype_init(void)
{
	sttype_register_integer();
	sttype_register_pointer();
	sttype_register_range();
	sttype_register_string();
	sttype_register_test();
}

void
sttype_cleanup(void)
{
	/* nothing to do */
}


void
sttype_register(sttype_t *type)
{
	sttype_id_t	type_id;

	type_id = type->id;

	/* Check input */
	g_assert(type_id < STTYPE_NUM_TYPES);

        /* Don't re-register. */
        g_assert(type_list[type_id] == NULL);

        type_list[type_id] = type;
}

static sttype_t*
sttype_lookup(sttype_id_t type_id)
{
	sttype_t	*result;

	/* Check input */
	g_assert(type_id < STTYPE_NUM_TYPES);

	result = type_list[type_id];

	/* Check output. */
        g_assert(result != NULL);

        return result;
}


stnode_t*
stnode_new(sttype_id_t type_id, gpointer data)
{
	sttype_t	*type;
	stnode_t	*node;

	node = g_new(stnode_t, 1);
	node->magic = STNODE_MAGIC;

	if (type_id == STTYPE_UNINITIALIZED) {
		node->type = NULL;
		node->data = NULL;
	}
	else {
		type = sttype_lookup(type_id);
		g_assert(type);
		node->type = type;
		if (type->func_new) {
			node->data = type->func_new(data);
		}
		else {
			node->data = data;
		}

	}

	return node;
}

void
stnode_init(stnode_t *node, sttype_id_t type_id, gpointer data)
{
	sttype_t	*type;

	assert_magic(node, STNODE_MAGIC);
	g_assert(!node->type);
	g_assert(!node->data);

	type = sttype_lookup(type_id);
	g_assert(type);
	node->type = type;
	if (type->func_new) {
		node->data = type->func_new(data);
	}
	else {
		node->data = data;
	}
}

void
stnode_init_int(stnode_t *node, sttype_id_t type_id, guint32 value)
{
	stnode_init(node, type_id, NULL);
	node->value = value;
}

void
stnode_free(stnode_t *node)
{
	assert_magic(node, STNODE_MAGIC);
	if (node->type) {
		if (node->type->func_free) {
			node->type->func_free(node->data);
		}
	}
	else {
		g_assert(!node->data);
	}
	g_free(node);
}

const char*
stnode_type_name(stnode_t *node)
{
	assert_magic(node, STNODE_MAGIC);
	if (node->type)
		return node->type->name;
	else
		return "UNINITIALIZED";
}

sttype_id_t
stnode_type_id(stnode_t *node)
{
	assert_magic(node, STNODE_MAGIC);
	if (node->type)
		return node->type->id;
	else
		return STTYPE_UNINITIALIZED;
}

gpointer
stnode_data(stnode_t *node)
{
	assert_magic(node, STNODE_MAGIC);
	return node->data;
}

guint32
stnode_value(stnode_t *node)
{
	assert_magic(node, STNODE_MAGIC);
	return node->value;
}
