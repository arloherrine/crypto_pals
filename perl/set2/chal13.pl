#!/usr/bin/perl
use strict;
use bytes;
use MIME::Base64;

require '../utils/crypt.pl';
require '../utils/pkcs_7_pad.pl';
require '../utils/crypt-analysis.pl';

our $secret_key = join('', map(chr(int(rand(90)) + 35), 1 .. 16)); # random 16 readable characters

sub query_string_parse {
    my ($input) = @_;
    my %object = ();
    for (split(/&/, $input)) {
        my ($key, $value) = split(/=/, $_);
        $object{$key} = $value;
    }
    return %object;
}

sub profile_for {
    my ($email) = @_;
    $email =~ s/(&|=).*//;
    #my $uid = int(rand(1000));
    #return "email=$email&uid=$uid&role=user";
    return "email=$email&uid=10&role=user";
}

sub encrypted_profile_for {
    my $encoded = profile_for(@_);
    return ecb_encrypt($secret_key, $encoded);
}

sub parse_encrypted_profile {
    my ($ciphertext) = @_;
    my $encoded = ecb_decrypt($secret_key, $ciphertext);
    return query_string_parse($encoded);
}

sub differing_block_index {
    my ($a, $b, $block_size) = @_;
    my @a_blocks = unpack("(a$block_size)*", $a);
    my @b_blocks = unpack("(a$block_size)*", $b);
    for (0 .. (length($a) / $block_size)) {
        return $_ if $a_blocks[$_] ne $b_blocks[$_];
    }
}

sub find_prefix_length {
    my ($block_size) = @_;
    my $input = 'A' x ($block_size + 1); # this makes it part of EXACTLY two blocks
    my $a = encrypted_profile_for($input);

    substr($input, 0, 1) = 'B';
    my $b = encrypted_profile_for($input);

    my $differing_block_index = differing_block_index($a, $b, $block_size);
    my $i = 0;
    do {
        substr($input, $i++, 2) = 'AB';
        $b = encrypted_profile_for($input);
    } while ($differing_block_index == differing_block_index($a, $b, $block_size));
    
    return ($differing_block_index * $block_size) + ($block_size - $i);
}

sub create_admin_profile {
    my ($block_size, $extra_stuff_size) = detect_block_size(\&encrypted_profile_for);
    
    my $email_pad = 'A' x ($block_size - length('email='));
    my $admin_payload = pkcs_7_pad('admin', $block_size);
    my $suffix_pad = 'A' x ($block_size - length('&uid=10&role='));

    my $encrypted = encrypted_profile_for("$email_pad$admin_payload$suffix_pad");

    my $payload_block = substr($encrypted, $block_size, $block_size);

    $encrypted = encrypted_profile_for('a@nothing.com');
    substr($encrypted, 2 * $block_size) = $payload_block;
    return $encrypted;
}

my $encrypted = create_admin_profile();
my %profile = parse_encrypted_profile($encrypted);

for (keys %profile) { print "$_: $profile{$_}\n" }

