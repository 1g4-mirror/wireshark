/*
 * $Id: ftype-double.c,v 1.5 2002/02/05 22:50:17 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 2001 Gerald Combs
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

#include <ftypes-int.h>
#include <stdlib.h>
#include <math.h>
#include <errno.h>

static void
double_fvalue_new(fvalue_t *fv)
{
	fv->value.floating = 0.0;
}

static void
double_fvalue_set_floating(fvalue_t *fv, gdouble value)
{
	fv->value.floating = value;
}

static double
value_get_floating(fvalue_t *fv)
{
	return fv->value.floating;
}

static gboolean
val_from_string(fvalue_t *fv, char *s, LogFunc logfunc)
{
	char    *endptr = NULL;

	fv->value.floating = strtod(s, &endptr);

	if (endptr == s || *endptr != '\0') {
		/* This isn't a valid number. */
		logfunc("\"%s\" is not a valid number.", s);
		return FALSE;
	}
	if (errno == ERANGE) {
		if (fv->value.floating == 0) {
			logfunc("\"%s\" causes floating-point underflow.", s);
		}
		else if (fv->value.floating == HUGE_VAL) {
			logfunc("\"%s\" causes floating-point overflow.", s);
		}
		else {
			logfunc("\"%s\" is not a valid floating-point number.",
			    s);
		}
		return FALSE;
	}

	return TRUE;
}


static gboolean
cmp_eq(fvalue_t *a, fvalue_t *b)
{
	return a->value.floating == b->value.floating;
}

static gboolean
cmp_ne(fvalue_t *a, fvalue_t *b)
{
	return a->value.floating != b->value.floating;
}

static gboolean
cmp_gt(fvalue_t *a, fvalue_t *b)
{
	return a->value.floating > b->value.floating;
}

static gboolean
cmp_ge(fvalue_t *a, fvalue_t *b)
{
	return a->value.floating >= b->value.floating;
}

static gboolean
cmp_lt(fvalue_t *a, fvalue_t *b)
{
	return a->value.floating < b->value.floating;
}

static gboolean
cmp_le(fvalue_t *a, fvalue_t *b)
{
	return a->value.floating <= b->value.floating;
}

void
ftype_register_double(void)
{

	static ftype_t double_type = {
		"FT_DOUBLE",
		"floating point",
		0,
		double_fvalue_new,
		NULL,
		val_from_string,

		NULL,
		NULL,
		double_fvalue_set_floating,

		NULL,
		NULL,
		value_get_floating,

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,

		NULL,
		NULL,
	};

	ftype_register(FT_DOUBLE, &double_type);
}
