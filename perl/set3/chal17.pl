use strict;

require '../utils/crypt.pl';
require '../utils/pkcs_7_pad.pl';

our @tokens = (
    'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
    'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
    'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
    'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
    'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
    'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
    'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
    'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
    'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
    'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93',
);
our $secret_key = random_key();

sub encrypted_token {
    my $token = $tokens[int(rand(scalar(@tokens)))];
    my $iv = "\x00" x 16;
    return (cbc_encrypt($secret_key, $token, $iv), $iv);
}

sub valid_token {
    my ($encrypted) = @_;
    my $token = cbc_decrypt($secret_key, $encrypted);
    eval {
        validate_strip_pkcs7($token);
        return 1;
    } or do {
        return 0;
    };
}

sub decrypt_token {
    my ($encrypted, $iv) = encrypted_token();
    my @blocks = unpack('(a16)*', $encrypted);
    my $decrypted = '';
    my $prev_block = $iv;
    for (@blocks) {
        $decrypted .= decrypt_token_block($prev_block, $_);
        $prev_block = $_;
    }
    
    eval {
        return validate_strip_pkcs7($decrypted);
    } or do {
        return $decrypted;
    }
}

sub decrypt_token_block {
    my ($prev, $en_block, $de_block, $pos) = @_;
    my $prev_xor_prefix = "\x00" x (15 - $pos);
    my $prev_xor_suffix = $de_block ^ (chr($pos + 1) x $pos);
    for my $byte (0 .. 0xff) {
        if (valid_token(($prev ^ ($prev_xor_prefix . chr($byte) . $prev_xor_suffix)) . $en_block)) {
            my $new_de_block = chr($byte ^ ($pos + 1)) . $de_block;
            if ($pos == 15) {
                return $new_de_block;
            } else {
                my $possible =  decrypt_token_block($prev, $en_block, $new_de_block, $pos + 1);
                return $possible if $possible;
            }
        }
    }
}

my $result = decrypt_token();
print "$result\n";

