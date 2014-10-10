use strict;

require '../utils/crypt.pl';
require '../utils/pkcs_7_pad.pl';

our $secret_key = join('', map chr(int(rand(2**8))), 1 .. 16);
our $prefix = 'comment1=cooking%20MCs;userdata=';
our $suffix = ';comment2=%20like%20a%20pound%20of%20bacon';

sub wrap_user_data {
    my ($user_data) = @_;
    $user_data =~ s/;/%3B/g;
    $user_data =~ s/=/%3D/g;
    my $plain = "$prefix$user_data$suffix";
    return cbc_encrypt($secret_key, $plain);
}

sub is_admin {
    my ($encrypted) = @_;
    my $plain = cbc_decrypt($secret_key, $encrypted);
    return $plain =~ /(^|;)admin=true(;|$)/;
}

sub become_admin {
    my $prefix_pad = -length($prefix) % 16;
    my $cipher = wrap_user_data("\x00" x ($prefix_pad + 32));
    my $offset = length($prefix) + $prefix_pad;
    substr($cipher, $offset, 16) = substr($cipher, $offset, 16) ^ 'other;admin=true';
    if (is_admin($cipher)) {
        print "lulz, got hacked\n";
    } else {
        print "hack failed!\n";
    }
}

become_admin();

