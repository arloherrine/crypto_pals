#!/usr/bin/perl
use strict;
use bytes;
use MIME::Base64;

require '../utils/crypt.pl';
require '../utils/ecb-oracle.pl';
require '../utils/crypt-analysis.pl';

our $rand_key = join('', map(chr(int(rand(2**8))), 1 .. 16));
our $rand_prefix = join('', map(chr(int(rand(2**8))), 0 .. (int(rand(40) + 3))));
our $target_bytes = decode_base64('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK');

sub random_crypt {
    my ($input) = @_;
    my $ciphertext = "$rand_prefix$input$target_bytes";
    return ecb_encrypt($rand_key, $ciphertext);
}

sub first_different_block {
    my ($a_ref, $b_ref) = @_;
    for (0 .. scalar(@$a_ref)) {
        return $_ if @$a_ref[$_] ne @$b_ref[$_];
    }
}
    
sub find_prefix_sizes {
    my ($block_size, $extras_size) = @_;
    my $filler_size = $block_size - ($extras_size % $block_size) + $block_size;

    my @original_blocks = unpack("(a$block_size)*", random_crypt('A' x $filler_size));
    
    my @fully_infected_blocks = unpack("(a$block_size)*", random_crypt('B' x $filler_size));
    my $front_infect_block = first_different_block(\@original_blocks, \@fully_infected_blocks);

    for my $i (1 .. $filler_size) {
        my @part_infected_blocks = unpack("(a$block_size)*", random_crypt(
                ('A' x $i) . ('B' x ($filler_size - $i))));
        return ($front_infect_block,  $block_size - $i)
            if first_different_block(\@original_blocks, \@part_infected_blocks) != $front_infect_block;
    }
    die "Failed to find prefix size";
}
    

sub decrypt_unknown_string {
    my ($block_size, $extras_size) = detect_block_size(\&random_crypt);
    die "block size should be 16 but was $block_size" unless $block_size == 16;
    die "failed to detect ecb" unless is_ecb_encoded(random_crypt('A' x 100));

    my ($prefix_blocks, $prefix_bytes) = find_prefix_sizes($block_size, $extras_size);
    my $block_fill = 'A' x ($block_size - $prefix_bytes);
    my $target_size = $extras_size - ($block_size * $prefix_blocks) - $prefix_bytes;

    my $unknown_string = '';
    for my $block_index (($prefix_blocks + 1) .. int($extras_size / $block_size) + 1) {
        for my $i (reverse 0 .. ($block_size - 1)) {
            my %dict_of_evil = ();
            for (0 .. (2**8 - 1)) {
                my $output = random_crypt($block_fill . ('A' x $i) . $unknown_string . chr($_));
                $dict_of_evil{substr($output, $block_index * $block_size, $block_size)} = chr($_);
            }
            my $output = random_crypt($block_fill . ('A' x $i));
            $unknown_string .= $dict_of_evil{substr($output, $block_index * $block_size, $block_size)};
            if (length($unknown_string) >= $target_size) {
                return $unknown_string;
            }
        }
    }
    return $unknown_string;
}

print decrypt_unknown_string() . "\n";

