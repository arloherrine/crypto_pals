#!/usr/bin/perl
use strict;
use bytes;
use MIME::Base64;

require '../utils/crypt.pl';
require '../utils/ecb-oracle.pl';
require '../utils/crypt-analysis.pl';

our $unknown_key = join('', map(chr(int(rand(90)) + 35), 1 .. 16)); # random 16 readable characters

sub random_crypt {
    my ($input) = @_;
    my $weird_suffix = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK';
    $input .= decode_base64($weird_suffix);
    return ecb_encrypt($unknown_key, $input);
}

sub decrypt_unknown_string {
    my ($block_size, $unknown_string_size) = detect_block_size(\&random_crypt);
    die "block size should be 16 but was $block_size" unless $block_size == 16;
    die "failed to detect ecb" unless is_ecb_encoded(random_crypt('A' x 100));

    my $unknown_string = '';
    for my $block_index (0 .. int($unknown_string_size / $block_size)) {
        for my $i (1 .. $block_size) {
            my %dict_of_evil = ();
            for (0 .. (2**8 - 1)) {
                my $output = random_crypt(('A' x ($block_size - $i)) . $unknown_string . chr($_));
                $dict_of_evil{substr($output, $block_index * $block_size, $block_size)} = chr($_);
            }
            my $output = random_crypt('A' x ($block_size - $i));
            $unknown_string .= $dict_of_evil{substr($output, $block_index * $block_size, $block_size)};
            if (length($unknown_string) >= $unknown_string_size) {
                return $unknown_string;
            }
        }
        $block_index++;
    }
    return $unknown_string;
}

print decrypt_unknown_string() . "\n";

