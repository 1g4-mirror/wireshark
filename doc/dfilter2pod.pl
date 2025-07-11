#!/usr/bin/perl
#
# Reads the display filter keyword dump produced by 'ethereal -G' and
# formats it for a pod document. The pod document is then used to
# make a manpage
#
# STDIN is the ethereal glossary
# arg1 is the pod template file. The =insert_dfilter_table token
#	will be replaced by the pod-formatted glossary
# STDOUT is the output
#
# $Id: dfilter2pod.pl,v 1.2 2001/04/19 23:17:30 guy Exp $

%ftenum_names = (
	'FT_NONE',		'No value',
	'FT_PROTOCOL',	'Protocol',
	'FT_BOOLEAN',		'Boolean',
	'FT_UINT8',		'Unsigned 8-bit integer',
	'FT_UINT16',		'Unsigned 16-bit integer',
	'FT_UINT24',		'Unsigned 24-bit integer',
	'FT_UINT32',		'Unsigned 32-bit integer',
	'FT_INT8',		'Signed 8-bit integer',
	'FT_INT16',		'Signed 16-bit integer',
	'FT_INT24',		'Signed 24-bit integer',
	'FT_INT32',		'Signed 32-bit integer',
	'FT_DOUBLE',		'Double-precision floating point',
	'FT_ABSOLUTE_TIME',	'Date/Time stamp',
	'FT_RELATIVE_TIME',	'Time duration',
	'FT_STRING',		'String',
	'FT_STRINGZ',		'String',
	'FT_ETHER',		'6-byte Hardware (MAC) Address',
	'FT_BYTES',		'Byte array',
	'FT_IPv4',		'IPv4 address',
	'FT_IPv6',		'IPv6 address',
	'FT_IPXNET',		'IPX network or server name',
);

# Read all the data into memory
while (<STDIN>) {
	next unless (/^([PF])/);

	$record_type = $1;
	chomp($_);

	# Store protocol information
	if ($record_type eq 'P') {
		($junk, $name, $abbrev) = split(/\t+/, $_);
		$proto_abbrev{$name} = $abbrev;
	}
	# Store header field information
	else {
		($junk, $name, $abbrev, $type, $parent) =
			split(/\t+/, $_);
		push(@{$field_abbrev{$parent}}, $abbrev);
		$field_info{$abbrev} = [ $name, $type ];
	}
}

# if there was no input on stdin, bail out
if ($record_type ne 'P' and $record_type ne 'F') {
	exit;
}

$template = shift(@ARGV);

open(TEMPLATE, $template) || die "Can't open $template for reading: $!\n";

while (<TEMPLATE>) {
	if (/=insert_dfilter_table/) {
		&create_dfilter_table;
	}
	else {
		print;
	}
}

close(TEMPLATE) || die "Can't close $template: $!\n";

sub create_dfilter_table {

	# Print each protocol
	for $proto_name (sort keys %proto_abbrev) {

		print "=head2 $proto_name ($proto_abbrev{$proto_name})\n\n";

		# If this proto has children fields, print those
		if ($field_abbrev{$proto_abbrev{$proto_name}}) {

			for $field_abbrev (sort @{$field_abbrev{$proto_abbrev{$proto_name}}}) {
				print "    $field_abbrev  ", $field_info{$field_abbrev}[0],"\n";
				print "        ", $ftenum_names{$field_info{$field_abbrev}[1]}, "\n\n";
			}
		}
	}
}
