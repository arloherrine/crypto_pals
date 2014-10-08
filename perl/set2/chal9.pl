#!/user/bin/perl
use strict;

require '../utils/pkcs_7_pad.pl';

my ($input, $block_size) = length(@ARGV) == 2 ? @ARGV : ("YELLOW SUBMARINE", 20);
my $padded = pkcs_7_pad($input, $block_size);
my $hex = unpack('H*', $padded);
print "$hex\n";

$padded =~ s/\x04/\\x04/g;
print "$padded\n";
