#!/user/bin/perl
use strict;

my ($input, $block_size) = length(@ARGV) == 2 ? @ARGV : ("YELLOW SUBMARINE", 20);
my $pad_length = $block_size - (length($input) % $block_size);
my $padded = $input . (chr($pad_length) x $pad_length);

my $hex = unpack('H*', $padded);
print "$hex\n";

$padded =~ s/\x04/\\x04/g;
print "$padded\n";
