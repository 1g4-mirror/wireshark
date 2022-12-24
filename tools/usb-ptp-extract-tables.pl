#!/usr/bin/perl -w
# 
# $Id$
# 
# USB PTP Dissector
#    Extracts PTP response codes from libgphoto2
#  This is then hand-merged into packet-usb-ptp.h
# 
# (c)2013 Max Baker <max@warped.org>
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

$file = shift @ARGV || 'ptp.h';

%tables = (
'PTP_AC' => 'StorageInfo Access Capability',
'PTP_AT' => 'Association Types',
'PTP_DPC' => 'Device Properties Codes',
'PTP_DPFF' => 'Device Property Form Flag',
'PTP_DPGS' => 'Device Property GetSet type',
'PTP_DTC' => 'Data Type Codes',
'PTP_EC' => 'Event Codes',
'PTP_FST' => 'FilesystemType Values',
'PTP_GOH' => 'GetObjectHandles',
'PTP_OC' => 'Operation Codes',
'PTP_OFC' => 'Object Format Codes',
'PTP_OPC' => 'MTP Object Properties',
'PTP_OPFF' => 'MTP Device Property Codes',
'PTP_PS' => 'Protection Status',
'PTP_RC' => 'Response Codes',
'PTP_ST' => 'Storage Types',
'PTP_FLAVOR' => 'Vendor IDs',
);

%Flavors = qw/
ANDROID     USB_PTP_FLAVOR_ANDROID
CANON       USB_PTP_FLAVOR_CANON
CANON_EOS   USB_PTP_FLAVOR_CANON
CASIO       USB_PTP_FLAVOR_CASIO
EK          USB_PTP_FLAVOR_KODAK
FUJI        USB_PTP_FLAVOR_FUJI
MTP         USB_PTP_FLAVOR_MTP
NIKON       USB_PTP_FLAVOR_NIKON
OLYMPUS     USB_PTP_FLAVOR_OLYMPUS
/;

$re_hex = '0x[0-9a-f]+';

open (H,"<$file") or die;
while (<H>) {
    chomp;

    next unless /^\s*#define\s+(\S+)\s+(.*)$/;
    
    my ($define,$val) = ($1,$2);
    # strip c-style comment
    $val =~ s,/\*.*\*/,,;
    $val =~ s,//.*,,;
    $val =~ s/^\s*//g;
    $val =~ s/\s*$//g;

    #print "$define=$val\n";
    $D{$define}=$val;
}

close H;

# Output tables
foreach my $table (sort keys %tables) {
    output_table($table, $tables{$table});
}

sub output_table {
    my ($table,$desc) = @_;

    my $id = lc($table);
    $id =~ s/^PTP_//i;

    print "/* $table $desc */\n";
    print "static const value_string_masked usb_ptp_${id}_mvals\[\] = {\n";
    my @vals;
    DEFINE:
    foreach my $define (sort sort_D keys %D) {
        next unless $define =~ /^${table}_(.*)/i;
        my $subdefine = $1;

        my $type = 'USB_PTP_FLAVOR_ALL';
        foreach my $flavor (sort {length($b) <=> length($a)} keys %Flavors) {
            next unless $subdefine =~ s/^${flavor}_//i;
            $type = $Flavors{$flavor}
        }

        # Ok, not a subflavor
        push @vals, sprintf("    {%-25s, %s, \"%s\"}",$type,lc($D{$define}),$subdefine);
    }
    print join(",\n",@vals),"\n";
    print "};\n";
}


sub sort_D {
    my $aa = $D{$a};
    $aa = hex($aa) if $aa=~/^${re_hex}$/i;
    $bb = $D{$b} || $b;
    $bb = hex($bb) if $bb=~/^${re_hex}$/i;

    if ($aa =~ /^\d+$/ and $bb=~/^\d+$/) {
        return $aa <=> $bb;
    }
    return $aa cmp $bb;
}
