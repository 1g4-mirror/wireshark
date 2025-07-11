/*
 * $Id: ftype-time.c,v 1.16 2002/02/05 22:50:17 guy Exp $
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

#include <ctype.h>
#include <string.h>

/*
 * Just make sure we include the prototype for strptime as well
 * (needed for glibc 2.2)
 */
#define __USE_XOPEN

#include <time.h>

#include <ftypes-int.h>

#ifdef NEED_STRPTIME_H
#include "strptime.h"
#endif

static gboolean
cmp_eq(fvalue_t *a, fvalue_t *b)
{
	return ((a->value.time.secs) ==(b->value.time.secs))
	     &&((a->value.time.nsecs)==(b->value.time.nsecs));
}
static gboolean
cmp_ne(fvalue_t *a, fvalue_t *b)
{
	return (a->value.time.secs !=b->value.time.secs)
	     ||(a->value.time.nsecs!=b->value.time.nsecs);
}
static gboolean
cmp_gt(fvalue_t *a, fvalue_t *b)
{
	if (a->value.time.secs > b->value.time.secs) {
		return TRUE;
	}
	if (a->value.time.secs < b->value.time.secs) {
		return FALSE;
	}

	return a->value.time.nsecs > b->value.time.nsecs;
}
static gboolean
cmp_ge(fvalue_t *a, fvalue_t *b)
{
	if (a->value.time.secs > b->value.time.secs) {
		return TRUE;
	}
	if (a->value.time.secs < b->value.time.secs) {
		return FALSE;
	}

	return a->value.time.nsecs >= b->value.time.nsecs;
}
static gboolean
cmp_lt(fvalue_t *a, fvalue_t *b)
{
	if (a->value.time.secs < b->value.time.secs) {
		return TRUE;
	}
	if (a->value.time.secs > b->value.time.secs) {
		return FALSE;
	}

	return a->value.time.nsecs < b->value.time.nsecs;
}
static gboolean
cmp_le(fvalue_t *a, fvalue_t *b)
{
	if (a->value.time.secs < b->value.time.secs) {
		return TRUE;
	}
	if (a->value.time.secs > b->value.time.secs) {
		return FALSE;
	}

	return a->value.time.nsecs <= b->value.time.nsecs;
}


/*
 * Get a nanoseconds value, starting at "p".
 *
 * Returns true on success, false on failure.
 */
static gboolean
get_nsecs(char *startp, int *nsecs)
{
	int ndigits;
	int scale;
	char *p;
	int val;
	int digit;
	int i;

	/*
	 * How many characters are in the string?
	 */
	ndigits = strlen(startp);

	/*
	 * If there are N characters in the string, the last of the
	 * characters would be the digit corresponding to 10^(9-N)
	 * nanoseconds.
	 */
	scale = 9 - ndigits;

	/*
	 * Start at the last character, and work backwards.
	 */
	p = startp + ndigits;
	val = 0;
	while (p != startp) {
		p--;

		if (!isdigit((unsigned char)*p)) {
			/*
			 * Not a digit - error.
			 */
			return FALSE;
		}
		digit = *p - '0';
		if (digit != 0) {
			/*
			 * Non-zero digit corresponding to that number
			 * of (10^scale) units.
			 *
			 * If scale is less than zero, this digit corresponds
			 * to a value less than a nanosecond, so this number
			 * isn't valid.
			 */
			if (scale < 0)
				return FALSE;
			for (i = 0; i < scale; i++)
				digit *= 10;
			val += digit;
		}
		scale++;
	}
	*nsecs = val;
	return TRUE;
}

static gboolean
relative_val_from_string(fvalue_t *fv, char *s, LogFunc logfunc)
{
	char    *curptr, *endptr;

	curptr = s;

	/*
	 * If it doesn't begin with ".", it should contain a seconds
	 * value.
	 */
	if (*curptr != '.') {
		/*
		 * Get the seconds value.
		 */
		fv->value.time.secs = strtoul(curptr, &endptr, 10);
		if (endptr == curptr || (*endptr != '\0' && *endptr != '.'))
			goto fail;
		curptr = endptr;
		if (*curptr == '.')
			curptr++;	/* skip the decimal point */
	} else {
		/*
		 * No seconds value - it's 0.
		 */
		fv->value.time.secs = 0;
		curptr++;		/* skip the decimal point */
	}

	/*
	 * If there's more stuff left in the string, it should be the
	 * nanoseconds value.
	 */
	if (*curptr != '\0') {
		/*
		 * Get the nanoseconds value.
		 */
		if (!get_nsecs(curptr, &fv->value.time.nsecs))
			goto fail;
	} else {
		/*
		 * No nanoseconds value - it's 0.
		 */
		fv->value.time.nsecs = 0;
	}

	/*
	 * XXX - what about negative values?
	 */
	return TRUE;

fail:
	if (logfunc != NULL)
		logfunc("\"%s\" is not a valid time.", s);
	return FALSE;
}


static gboolean
absolute_val_from_string(fvalue_t *fv, char *s, LogFunc logfunc)
{
	struct tm tm;
	char    *curptr;

	curptr = strptime(s,"%b %d, %Y %H:%M:%S", &tm);
	if (curptr == NULL)
		goto fail;
	tm.tm_isdst = -1;	/* let the computer figure out if it's DST */
	fv->value.time.secs = mktime(&tm);
	if (*curptr != '\0') {
		/*
		 * Something came after the seconds field; it must be
		 * a nanoseconds field.
		 */
		if (*curptr != '.')
			goto fail;	/* it's not */
		curptr++;	/* skip the "." */
		if (!isdigit((unsigned char)*curptr))
			goto fail;	/* not a digit, so not valid */
		if (!get_nsecs(curptr, &fv->value.time.nsecs))
			goto fail;
	} else {
		/*
		 * No nanoseconds value - it's 0.
		 */
		fv->value.time.nsecs = 0;
	}

	if (fv->value.time.secs == -1) {
		/*
		 * XXX - should we supply an error message that mentions
		 * that the time specified might be syntactically valid
		 * but might not actually have occurred, e.g. a time in
		 * the non-existent time range after the clocks are
		 * set forward during daylight savings time (or possibly
		 * that it's in the time range after the clocks are set
		 * backward, so that there are two different times that
		 * it could be)?
		 */
		goto fail;
	}

	return TRUE;

fail:
	if (logfunc != NULL)
		logfunc("\"%s\" is not a valid absolute time. Example: \"Nov 12, 1999 08:55:44.123\"",
		    s);
	return FALSE;
}

static void
time_fvalue_new(fvalue_t *fv)
{
	fv->value.time.secs = 0;
	fv->value.time.nsecs = 0;
}

static void
time_fvalue_set(fvalue_t *fv, gpointer value, gboolean already_copied)
{
	g_assert(!already_copied);
	memcpy(&(fv->value.time), value, sizeof(nstime_t));
}

static gpointer
value_get(fvalue_t *fv)
{
	return &(fv->value.time);
}

void
ftype_register_time(void)
{

	static ftype_t abstime_type = {
		"FT_ABSOLUTE_TIME",
		"date/time",
		0,
		time_fvalue_new,
		NULL,
		absolute_val_from_string,

		time_fvalue_set,
		NULL,
		NULL,

		value_get,
		NULL,
		NULL,

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
		NULL,
		NULL
	};
	static ftype_t reltime_type = {
		"FT_RELATIVE_TIME",
		"time offset",
		0,
		time_fvalue_new,
		NULL,
		relative_val_from_string,

		time_fvalue_set,
		NULL,
		NULL,

		value_get,
		NULL,
		NULL,

		cmp_eq,
		cmp_ne,
		cmp_gt,
		cmp_ge,
		cmp_lt,
		cmp_le,
		NULL,
		NULL
	};

	ftype_register(FT_ABSOLUTE_TIME, &abstime_type);
	ftype_register(FT_RELATIVE_TIME, &reltime_type);
}
