#!/usr/bin/perl
use strict;

use Crypt::Mode::ECB;
use MIME::Base64;


my $m = Crypt::Mode::ECB->new('AES');
my @lines = <STDIN>;
my $base64 = join('', @lines);
my $input = decode_base64($base64);
my $plaintext = $m->decrypt($input, 'YELLOW SUBMARINE');
print "$plaintext";

