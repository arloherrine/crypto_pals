use strict;

sub pkcs_7_pad {
    my ($input, $block_size) = @_;
    $block_size = 16 unless $block_size;
    my $pad_length = -length($input) % $block_size;
    $input .= chr($pad_length) x ($pad_length);
    return $input;
}

sub validate_strip_pkcs7 {
    my ($input, $block_size) = @_;
    $block_size = 16 unless $block_size;
    die "Input length is not multiple of block size" if length($input) % $block_size;
    my $pad_num = ord(substr($input, -1, 1));
    die "Padding character is zero" unless $pad_num;
    die "Padding character is not smaller than the block size" if $pad_num > $block_size;
    for (1 .. $pad_num) {
        die "Invalid pad character: $_" if ord(substr($input, -$_, 1)) != $pad_num;
    }
    return substr($input, 0, length($input) - $pad_num);
}

1;
