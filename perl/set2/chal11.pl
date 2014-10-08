#!/usr/bin/perl
use strict;
use bytes;
use MIME::Base64;

require '../utils/crypt.pl';
require '../utils/ecb-oracle.pl';

sub random_bytes {
    my ($length) = @_;
    return join('', map(chr(int(rand(2**8))), 1 .. $length));
}

sub random_crypt {
    my ($input) = @_;
    my ($output, undef) = _random_crypt($input);
    return $output;
}

sub _random_crypt {
    my ($input) = @_;
    $input = random_bytes(int(rand(6)) + 5) . $input . random_bytes(int(rand(6)) + 5);
    my $key = random_bytes(16);
    if (int(rand(2))) {
        return (cbc_encrypt($key, $input), 1);
    } else {
        return (ecb_encrypt($key, $input), 0);
    }
}

sub detect_block_mode {
    my ($input) = @_;
    if (is_ecb_encoded($input, 16)) {
        return 'ecb';
    } else {
        return 'cbc';
    }
}

sub test_oracle {
    my $input = 'A' x 50;
    my ($output, $actual_is_cbc) = _random_crypt($input);
    my $actual_mode = $actual_is_cbc ? 'cbc' : 'ecb';
    my $detected_mode = detect_block_mode($output);
    if ($detected_mode eq $actual_mode) {
        return "Correctly detected $detected_mode mode.\n";
    } else {
        return "**** FAIL: Detected $detected_mode but was $actual_mode.\n";
    }
}

print test_oracle();
print test_oracle();
print test_oracle();
print test_oracle();
print test_oracle();

