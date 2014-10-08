use strict;
use bytes;

sub detect_block_size {
    my ($crypt_func) = @_;
    my ($previous_cipher_size, $cipher_size);
    my $input_size = 0;
    $previous_cipher_size = $cipher_size = length($crypt_func->('A' x ++$input_size));
    while ($cipher_size == $previous_cipher_size) {
        $previous_cipher_size = $cipher_size;
        $cipher_size = length($crypt_func->('A' x ++$input_size));
    }
    return ($cipher_size - $previous_cipher_size, $previous_cipher_size - $input_size + 1)
}

1;
