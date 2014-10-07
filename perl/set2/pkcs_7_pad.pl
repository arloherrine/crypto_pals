
sub pkcs_7_pad {
    my ($input, $block_size) = @_;
    my $extra_chars = (length($input) % $block_size);
    $input .= chr($pad_length) x ($block_size - $extra_chars) if $extra_chars;
    return $input;
}

1;
