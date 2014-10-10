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
    $" = ' ';
    my @chunkers = unpack('(H32)*', $token);
    print "cheating token: @chunkers\n";
    my $iv = "\x00" x 16;
    return (cbc_encrypt($secret_key, $token, $iv), $iv);
}

sub valid_token {
    my ($encrypted) = @_;
    my $token = cbc_decrypt($secret_key, $encrypted);
    eval {
        validate_strip_pkcs7($token);
        print "valid token hex: " . unpack('H*', $token) . "\n";
        return 1;
    } or do {
        return 0;
    };
}

sub decrypt_token {
    my ($encrypted, $iv) = encrypted_token();
    my @blocks = unpack('(a16)*', $encrypted);
    #print "num blocks: " . scalar(@blocks) . ", should be " . length($encrypted) / 16 . "\n";
    my $decrypted = '';
    my $prev_block = $iv;
    for (@blocks) {
        $decrypted .= decrypt_token_block($prev_block, $_);
        $prev_block = $_;
    }
    
    $" = ' ';
    my @chunkers = unpack('(H32)*', $decrypted);
    print "decryptd token: @chunkers\n";
    return validate_strip_pkcs7($decrypted);
}

sub decrypt_token_block {
    my ($prev, $en_block) = @_;
    print "decrypting block: " . unpack('H*', $en_block) . "\n";
    print "block size: " . length($en_block) . "\n";
    #print "with prefx block: " . unpack('H*', $prev) . "\n";
    my $de_block = '';
    for my $pos (1 .. 16) {
        my $prev_xor_prefix = "\x00" x (16 - $pos);
        my $prev_xor_suffix = $de_block ^ (chr($pos) x ($pos - 1));
        for my $byte (0 .. 0xff) {
            if (valid_token(($prev ^ ($prev_xor_prefix . chr($byte) . $prev_xor_suffix)) . $en_block)) {
                $de_block = chr($byte ^ $pos) . $de_block;
                #print "adding: " . ($byte ^ $pos) . "\n";
                last;
            }
        }
    }
    return $de_block;
}

my $result = decrypt_token();
#print "decrypted token: $result\n";
#validate_strip_pkcs7("\x10" x 16);
#print "valid\n";

#sub last_byte_mask {
#    my ($cipher) = @_;
#    my $pre_len = length($cipher) - 17;
#    my ($pre, $target, $suf) = unpack("($pre_len)(a)(a16)", $cipher);
#    for (0 .. 0xFF) {
#        return chr($_) if valid_token($pre . ($target ^ chr($_)) . $suf);
#    }
#}

