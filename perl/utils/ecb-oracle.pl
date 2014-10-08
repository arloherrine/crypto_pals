use strict;
use bytes;

sub is_ecb_encoded {
    return _duplicate_blocks(@_);
}

sub _duplicate_blocks {
    my ($input, $block_size) = @_;
    my @blocks = unpack("(a$block_size)*", $input);
    my %unique_blocks = ();
    for (@blocks) {
        $unique_blocks{$_} += 1;
    }
    return scalar(@blocks) - scalar(keys(%unique_blocks));
}

1;
