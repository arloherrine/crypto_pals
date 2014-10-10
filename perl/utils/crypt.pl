use strict;
use Crypt::OpenSSL::AES;

require '../utils/pkcs_7_pad.pl';

sub random_key {
    my ($length) = @_;
    $length = 16 unless $length;
    return join('', map chr(int(rand(2**8))), 1 .. 16);
}

sub ctr_crypt {
    my ($key, $input, $nonce) = @_;
    my $keystream = '';
    my $counter;
    my $output = '';
    my $m = new Crypt::OpenSSL::AES($key);
    for (0 .. (length($input) - 1)) {
    #for (unpack('(a)*', $input)) {
        unless ($keystream) {
            my $to_crypt = pack('Q', $nonce) . pack('Q', $counter++);
            $keystream = $m->encrypt($to_crypt);
        }
        my $key_char = substr($keystream, 0, 1);
        substr($keystream, 0, 1) = '';
        $output .= substr($input, $_, 1) ^ $key_char;
    }
    return $output;
}

sub ecb_encrypt { return _ecb_crypt('true', @_) }
sub ecb_decrypt { return _ecb_crypt(0, @_) }

sub _ecb_crypt {
    my ($en, $key, $input) = @_;
    my $block_size = 16;
    $input = pkcs_7_pad($input, $block_size);
    my $m = new Crypt::OpenSSL::AES($key);
    my $output = '';
    for (my $i = 0; $i < length($input); $i += $block_size) {
        my $next_block = substr($input, $i, $block_size);
        $output .= $en ? $m->encrypt($next_block) : $m->decrypt($next_block);
    }
    return $output;
}

sub cbc_encrypt {
    my ($key, $input, $iv) = @_;
    return _cbc_crypt('true', $key, $input);
}

sub cbc_decrypt {
    my ($key, $input, $iv) = @_;
    return _cbc_crypt(0, $key, $input);
}

sub _cbc_crypt {
    my ($en, $key, $input, $iv) = @_;
    my $block_size = 16;
    $input = pkcs_7_pad($input, $block_size);
    my $m = new Crypt::OpenSSL::AES($key);

    my $last_cipher = $iv or chr(0) x $block_size;
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
