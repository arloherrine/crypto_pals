use strict;
use Crypt::OpenSSL::AES;

require 'pkcs_7_pad.pl';

sub cbc_encrypt {
    my ($key, $input) = @_;
    return _cbc_crypt('true', $key, $input);
}

sub cbc_decrypt {
    my ($key, $input) = @_;
    return _cbc_crypt(0, $key, $input);
}

sub _cbc_crypt {
    my ($en, $key, $input) = @_;
    my $block_size = 16;
    $input = pkcs_7_pad($input, $block_size);
    my $m = new Crypt::OpenSSL::AES($key);

    my $last_cipher = chr(0) x $block_size;
    my $output = '';
    for (my $i = 0; $i < length($input); $i += $block_size) {
        my $next_block = substr($input, $i, $block_size);
        if ($en) {
            $last_cipher = $m->encrypt($last_cipher ^ $next_block);
            $output .= $last_cipher;
        } else {
            $output .= $last_cipher ^ $m->decrypt($next_block);
            $last_cipher = $next_block;
        }
    }
    return $output;
}

1;
