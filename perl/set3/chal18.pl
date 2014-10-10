use strict;
use MIME::Base64;

require '../utils/crypt.pl';

my $input = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==';
my $result = ctr_crypt('YELLOW SUBMARINE', decode_base64($input));
print "$result\n";

