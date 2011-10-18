#!/usr/bin/perl 

use strict;
use warnings;
use Net::SSLeay qw(get_https);
use threads;

for my $i (1..50) {
   get_https('encrypted.google.com', 443, "/search?q=$i");
}
