#!/usr/bin/perl
use strict;
use bytes;
use MIME::Base64;

sub fromHex { return pack('H*', $_[0]) }
sub toHex { return unpack('H*', $_[0]) }

sub base64ToHex {
    my ($input) = @_;
    my $intermediate = decode_base64($input);
    return toHex($intermediate); 
}

sub hexToBase64 {
    my ($input) = @_;
    my $intermediate = fromHex($input);
    return encode_base64($intermediate);
}

sub fixedXor {
    my ($op1, $op2) = @_;
    return $op1 ^ $op2;
}

sub decrypt_single_char_xor_cipher {
    my ($input) = @_;
    my $length = length($input);
    my %freq_map = get_character_frequency_map_english();
    
    my ($best_score, $key, $result);
    for (0 .. 2**8) {
        my $repeated = chr($_) x $length;
        my $original = $repeated ^ $input;

        my $score = 0;
        for (split //, $original) {
            $score += $freq_map{$_} // -50;
        }
        if ($score > $best_score) {
            ($best_score, $key, $result) = ($score, chr($_), $original);
        }
    }
    return ($best_score, $key, $result);
}

sub find_single_char_xor_cipher {
    my ($best_score, $best_input, $best_output);
    for (@_) {
        my ($score, $key, $output) = decrypt_single_char_xor_cipher($_);
        if ($score > $best_score) {
            ($best_score, $best_input, $best_output) = ($score, $_, $output);
        }
    }
    return ($best_input, $best_output);
}

sub repeat_key_encrypt {
    my ($key, $input) = @_;
    my $key_len = length $key;
    my $input_len = length $input;
    my $repeated = ($key x ($input_len / $key_len)) . substr($key, 0, $input_len % $key_len);
    return $repeated ^ $input;
}

sub edit_distance {
    my ($str1, $str2) = @_;
    return unpack('%32b*', $str1 ^ $str2);
}
 
sub find_keysizes {
    my ($input) = @_;
    my %distances;
    for (2 .. 40) {
        my $chunk1 = substr($input, 0, $_);
        my $chunk2 = substr($input, $_, $_);
        my $chunk3 = substr($input, 2 * $_, $_);
        my $chunk4 = substr($input, 3 * $_, $_);

        my $dist_a = edit_distance($chunk1, $chunk2);
        my $dist_b = edit_distance($chunk3, $chunk4);

        my $distance = ($dist_a + $dist_b + 10) / (2 * $_);
        $distances{$_} = $distance;
    }

    return sort { $distances{$a} cmp $distances{$b} } 2 .. 40;
}

sub break_repeating_xor {
    my ($input) = @_;
    my @keysizes = find_keysizes($input);
    my %results = ();

    for my $keysize (@keysizes[0..2]) {
        my @transposes = transposed_chunks($input, $keysize);
 
        my $full_key = '';
        my $score_sum = 0;
        for (@transposes) {
            my ($score, $key, undef) = decrypt_single_char_xor_cipher($_);
            $full_key = $full_key . $key;
            $score_sum += $score;
        }
        my $final_score = $score_sum / $keysize;
        $results{$full_key} = $final_score if $full_key && $final_score > 0;
    }

    my @top_keys = sort { $results{$b} <=> $results{$a} } keys(%results);
    return $top_keys[0];
}

sub transposed_chunks {
    my ($input, $chunk_size) = @_;
    my @transposes = ();
    for (0 .. (length($input) - 1)) {
        $transposes[$_ % $chunk_size] .= substr($input, $_, 1);
    }
    return @transposes;
}

my @lines = <STDIN>;
my $base64 = join('', @lines);
my $input = decode_base64($base64);
my $key = break_repeating_xor($input);
print "$key\n";

sub get_character_frequency_map_english {
    my %freq_map = (
        "a" => 7.52766     ,
        "e" => 7.0925      ,
        "o" => 5.17        ,
        "r" => 4.96032     ,
        "i" => 4.69732     ,
        "s" => 4.61079     ,
        "n" => 4.56899     ,
        "1" => 4.35053     ,
        "t" => 3.87388     ,
        "l" => 3.77728     ,
        "2" => 3.12312     ,
        "m" => 2.99913     ,
        "d" => 2.76401     ,
        "0" => 2.74381     ,
        "c" => 2.57276     ,
        "p" => 2.45578     ,
        "3" => 2.43339     ,
        "h" => 2.41319     ,
        "b" => 2.29145     ,
        "u" => 2.10191     ,
        "k" => 1.96828     ,
        "4" => 1.94265     ,
        "5" => 1.88577     ,
        "g" => 1.85331     ,
        "9" => 1.79558     ,
        "6" => 1.75647     ,
        "8" => 1.66225     ,
        "7" => 1.621       ,
        "y" => 1.52483     ,
        "f" => 1.2476      ,
        "w" => 1.24492     ,
        "j" => 0.836677    ,
        "v" => 0.833626    ,
        "z" => 0.632558    ,
        "x" => 0.573305    ,
        "q" => 0.346119    ,
        "A" => 0.130466    ,
        "S" => 0.108132    ,
        "E" => 0.0970865   ,
        "R" => 0.08476     ,
        "B" => 0.0806715   ,
        "T" => 0.0801223   ,
        "M" => 0.0782306   ,
        "L" => 0.0775594   ,
        "N" => 0.0748134   ,
        "P" => 0.073715    ,
        "O" => 0.0729217   ,
        "I" => 0.070908    ,
        "D" => 0.0698096   ,
        "C" => 0.0660872   ,
        "H" => 0.0544319   ,
        "G" => 0.0497332   ,
        "K" => 0.0460719   ,
        "F" => 0.0417393   ,
        "J" => 0.0363083   ,
        "U" => 0.0350268   ,
        "W" => 0.0320367   ,
        "." => 0.0316706   ,
        "!" => 0.0306942   ,
        "Y" => 0.0255073   ,
        "*" => 0.0241648   ,
        "@" => 0.0238597   ,
        "V" => 0.0235546   ,
        "-" => 0.0197712   ,
        "Z" => 0.0170252   ,
        "Q" => 0.0147064   ,
        "X" => 0.0142182   ,
        "_" => 0.0122655   ,
        "\$" => 0.00970255  ,
        "#" => 0.00854313  ,
        "," => 0.00323418  ,
        "/" => 0.00311214  ,
        "+" => 0.00231885  ,
        "?" => 0.00207476  ,
        ";" => 0.00207476  ,
        "^" => 0.00195272  ,
        " " => 5.00189169  ,
        "%" => 0.00170863  ,
        "~" => 0.00152556  ,
        "=" => 0.00140351  ,
        "&" => 0.00134249  ,
        "`" => 0.00115942  ,
        "\\" => 0.00115942  ,
        ")" => 0.00115942  ,
        "]" => 0.0010984   ,
        "[" => 0.0010984   ,
        ":" => 0.000549201 ,
        "<" => 0.000427156 ,
        "(" => 0.000427156 ,
        "æ" => 0.000183067 ,
        ">" => 0.000183067 ,
        "\"" => 0.000183067 ,
        "ü" => 0.000122045 ,
        "|" => 0.000122045 ,
        "{" => 0.000122045 ,
        "'" => 0.000122045 ,
    );
    return %freq_map;
}
