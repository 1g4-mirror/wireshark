# Makefile.am
#
# $Id: Makefile.am,v 1.3 2001/02/27 20:34:09 gram Exp $
#
# Ethereal - Network traffic analyzer
# By Gerald Combs <gerald@zing.org>
# Copyright 2001 Gerald Combs
#
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

# We produce an archive library. In the future, when libethereal is a
# shared library, this will be linked into libethereal. While libethereal
# is an archive library, any executable linking against libethereal will
# also need to link against libftypes.

noinst_PROGRAMS = lemon

CLEANFILES = \
	*~

lemon_SOURCES = \
	lemon.c

EXTRA_DIST = \
	cppmagic.h		\
	lemon.html		\
	lemonflex-head.inc	\
	lemonflex-tail.inc	\
	lempar.c		\
	Makefile.nmake		\
	README

