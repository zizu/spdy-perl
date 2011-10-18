#!/usr/bin/perl 

use strict;
use warnings;
use Time::HiRes qw(sleep);
use SPDYClient;

my %headers = (
    'host'    => 'encrypted.google.com',
    'method'  => 'GET',
    'scheme'  => 'https',
    'url'     => '/search?q=1',
    'version' => 'HTTP/1.1'
);
my @tickets;
my $client = SPDYConnection->new('encrypted.google.com', 'https');
#for my $i (1..50) {
#    $headers{'url'} = "/search?q=$i";
#    $tickets[$i] = $client->add_stream(%headers);
#}
#$client->add_stream(%headers);
my $no = $client->add_stream(%headers);
#sleep 1;
#$client->_recv();
#sleep 0.1 while grep {not $client->is_ready($tickets[$_])} (1..50);

sleep 0.1 while not $client->is_ready(1);
my $resp =  $client->get(1);
if($resp->is_success) {
   print $resp->decoded_content();
}
else {
    print %$resp;
}
$client->close;


