/* strerror.c
 *
 * $Id: strerror.c,v 1.1 1999/06/14 21:46:36 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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

#include "strerror.h"

/*
 * Version of "strerror()", for the benefit of OSes that don't have it
 * (e.g., SunOS 4.x).
 */
char *
strerror(int errnum)
{
	extern int sys_nerr;
	extern char *sys_errlist[];
	static char errbuf[5+1+11+1];	/* "Error %d" */

	if (errnum < 0 || errnum >= sys_nerr) {
		sprintf(errbuf, "Error %d", errnum);
		return errbuf;
	} else
		return sys_errlist[errnum];
}
