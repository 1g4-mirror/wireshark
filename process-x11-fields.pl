#!/usr/bin/perl
#
# Script to convert "x11-fields" file, listing fields for
# X11 dissector, into header files declaring field-index
# values and field definitions for those fields.
#
# Copyright 2000, Christophe Tronche <ch.tronche@computer.org>
#
# $Id: process-x11-fields.pl,v 1.5 2001/06/18 02:17:58 guy Exp $
#
# Ethereal - Network traffic analyzer
# By Gerald Combs <gerald@ethereal.com>
# Copyright 1998 Gerald Combs
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#

open(DECL, ">x11-declarations.h") || die;
open(REG, ">x11-register-info.h") || die;

$prefix = '';
$subfieldStringLength = 0;

while(<>) {
    s/#.*$//go;
    next if /^\s*$/o;
    s/^(\s*)//o;
    $subfield = $1;

    if (length $subfield != $subfieldStringLength) {
	if (!length $subfield) {
	    $prefix = '';
	} elsif (length $subfield > $subfieldStringLength) {
	    $prefix .= "$lastAbbrev.";
	} else {
	    $prefix =~ s/^(.*)\.[^\.]+\.$/$1./o;
	}
	$subfieldStringLength = length $subfield;
    }

    @fields = split /\s+/o ;
    if ($fields[0] eq '#') {
	#
	# If the line begins with "#", treat it as a comment, by
	# ignoring it.
	#
	# (We don't support comments at the end of a line; that would
	# require some more pain in our simple parser.)
	#
	next;
    }
    $abbrev = shift @fields;
    $type = shift @fields;
    $lastAbbrev = $abbrev;

    $field = $prefix.$abbrev;

    if ($fields[0] =~ /^\d+$/o) {
	#
	# This is presumably a Boolean bitfield, and this is the number
	# of bits in the parent field.
	#
	$fieldDisplay = shift @fields;
    } else {
	#
	# The next token is the base for the field.
	#
	$fieldDisplay = "BASE_".shift @fields;
    }

    if ($fields[0] eq 'VALS') {
	#
	# It's an enumerated field, with the value_string table having a
	# name based on the field's name.
	#
	shift @fields;
	$fieldStrings = "VALS(${abbrev}_vals)";
	$fieldStrings =~ s/-/_/go;
    } elsif ($fields[0] =~ /^VALS\(/o) {
	#
	# It's an enumerated field, with a specified name for the
	# value_string table.
	#
	$fieldStrings = shift @fields;
	$fieldStrings =~ s/\)/_vals\)/o;
    } else {
	#
	# It's not an enumerated field.
	#
	$fieldStrings = 'NULL';
    }

    if ($fields[0] =~ /^0x/) {
	#
	# The next token looks like a bitmask for a bitfield.
	#
	$mask = shift @fields;
    } else {
	$mask = 0;
    }

    $rest = join(' ', @fields);
    $longName = uc $name;
    $longName = $rest if ($rest);

    $variable = $field;
    $variable =~ s/-/_/go;
    $variable =~ s/\./_/go;

    print DECL "static int hf_x11_$variable = -1;\n";

    print REG <<END;
{ &hf_x11_$variable, { "$abbrev", "x11.$field", FT_$type, $fieldDisplay, $fieldStrings, $mask, "$longName", HFILL }},
END
}
