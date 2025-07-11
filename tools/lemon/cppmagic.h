/* $Id: cppmagic.h,v 1.1 2001/02/27 20:34:09 gram Exp $ */

/**************************************** CPP definitions ***************/

/* CPP magic: Concatenate two strings or macros that resolve to strings.
 * Use CONCAT(), not _CONCAT() */
#define _CONCAT(a,b)		a ## b
#define CONCAT(a,b)		_CONCAT(a,b)

/* CPP magic: Surround a string or a macro that resolves to a string with
 * double quotes. */
#define _STRINGIFY(a)		# a
#define STRINGIFY(a)		_STRINGIFY(a)

