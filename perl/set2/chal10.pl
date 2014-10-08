#!/usr/bin/perl
use strict;
use MIME::Base64;

require '../utils/crypt.pl';

my $key = 'YELLOW SUBMARINE';
my $input = decode_base64(join('', <STDIN>));
my $output = cbc_decrypt($key, $input);
print "$output\n";

