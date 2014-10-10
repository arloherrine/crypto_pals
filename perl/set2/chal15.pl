use strict;

require '../utils/pkcs_7_pad.pl';

sub check_result {
    my ($input, $expected) = @_;
    my $output;
    eval {
        $output = validate_strip_pkcs7($input);
    } or do {
        die "Expected $expected, but was invalid" if $expected;
        print "Correctly found invalid\n";
        return;
    };
    die "Expected invalid, but was $output" unless $expected;
    die "Expected $expected but was $output" if $expected ne $output;
    print "Correctly found valid\n";
}

check_result('1CE ICE BABY' . (chr(4) x 4), '1CE ICE BABY');
check_result('2CE ICE BABY' . (chr(5) x 5));
check_result('2CE ICE BABY' . (chr(5) x 4));
check_result('3CE ICE BABY' . chr(1) . chr(2) . chr(3) . chr(4));
